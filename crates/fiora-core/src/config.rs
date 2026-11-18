//! Project configuration (`.fiora/config.json`) — persisted model defaults so
//! `fiora init` writes it once and every later command picks it up.

use std::fs;
use std::path::Path;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 命名模型条目（模型池）：一处配置、多处引用。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelSpec {
    /// pi 模型 id（如 mimo/mimo-v2.6-flash）
    pub model: String,
    /// 该模型默认思考档（可被命令行覆盖）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
}

/// 运行档位：一键切换「judge / budget」模型组合。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// 判定（深审）阶段引用的模型池名，或直接写模型 id
    pub judge: String,
    /// 省钱档（triage/P2/复核）引用的模型池名，或直接写模型 id
    pub budget: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectConfig {
    /// Default judge model (pi model id). None = pi's own default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Cheap model for triage / P2 batches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_model: Option<String>,
    /// Default thinking level for judge runs.
    #[serde(default = "default_thinking")]
    pub thinking_level: String,
    /// Custom endpoint (OpenAI-compatible gateway) for the default model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Env var name holding the API key (the key itself never lives here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    /// Wire protocol for the gateway: "openai-completions" | "openai-responses"
    /// | "anthropic-messages" | "google-generative-ai" | ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    /// 模型池：命名多模型（引用名 -> 模型规格）
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub models: BTreeMap<String, ModelSpec>,
    /// 运行档位：judge/budget 组合（引用模型池名或直接写模型 id）
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, Profile>,
    /// 当前生效档位（可被 --profile 覆盖）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<String>,
}

fn default_thinking() -> String {
    "xhigh".to_string()
}

impl Default for ProjectConfig {
    fn default() -> Self {
        ProjectConfig {
            default_model: None,
            budget_model: None,
            thinking_level: default_thinking(),
            base_url: None,
            api_key_env: None,
            api: None,
            models: BTreeMap::new(),
            profiles: BTreeMap::new(),
            active_profile: None,
        }
    }
}

impl ProjectConfig {
    /// Load from `<base>/config.json`; missing file or missing fields fall back
    /// to defaults (config is additive, never mandatory).
    pub fn load(base: &Path) -> Self {
        fs::read_to_string(base.join("config.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, base: &Path) -> std::io::Result<()> {
        fs::create_dir_all(base)?;
        fs::write(
            base.join("config.json"),
            serde_json::to_string_pretty(self).unwrap(),
        )
    }
}

/// 解析后的各阶段模型选择。
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedModels {
    /// judge 深审模型
    pub judge: Option<String>,
    /// 省钱档（triage / P2 / 复核）
    pub budget: Option<String>,
    /// judge 思考档
    pub thinking: Option<String>,
    /// 生效的档位名（用于日志/报告溯源）
    pub profile: Option<String>,
}

impl ProjectConfig {
    /// 模型解析优先级：显式 CLI > active/指定 profile > 默认槽。
    /// `profile` 为 `--profile` 覆盖；模型池名可嵌套解析一次。
    pub fn resolve_models(
        &self,
        cli_judge: Option<String>,
        cli_budget: Option<String>,
        profile: Option<&str>,
    ) -> ResolvedModels {
        let profile_name = profile
            .map(str::to_string)
            .or_else(|| self.active_profile.clone());
        let prof = profile_name.as_ref().and_then(|n| self.profiles.get(n));

        let slot = |cli: Option<String>, prof_slot: Option<&String>, fallback: &Option<String>| {
            cli.or_else(|| {
                prof_slot.and_then(|ref_name| {
                    // 模型池引用解析（一层），池中无同名则视为直接模型 id
                    self.models
                        .get(ref_name.as_str())
                        .map(|m| m.model.clone())
                        .or_else(|| Some(ref_name.clone()))
                })
            })
            .or_else(|| fallback.clone())
        };

        let judge = slot(cli_judge, prof.map(|p| &p.judge), &self.default_model);
        let budget = slot(cli_budget, prof.map(|p| &p.budget), &self.budget_model);
        let thinking = judge
            .as_ref()
            .and_then(|m| {
                let name = self
                    .models
                    .iter()
                    .find(|(_, spec)| &spec.model == m)
                    .map(|(n, _)| n.clone());
                name.and_then(|n| self.models.get(&n).and_then(|s| s.thinking.clone()))
            })
            .or(Some(self.thinking_level.clone()));

        ResolvedModels {
            judge,
            budget,
            thinking,
            profile: profile_name,
        }
    }
}
