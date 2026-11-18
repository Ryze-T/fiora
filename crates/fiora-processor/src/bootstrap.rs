//! Pi bootstrap (pi-domain): map Fiora's model config onto pi's documented
//! configuration surface — provider env vars for keys, `<agent-dir>/models.json`
//! for custom endpoints. Users configure the model through Fiora; they never
//! touch pi's internals.

use std::path::Path;

/// pi's documented provider API-key env vars (docs/providers.md).
pub fn provider_env_for(model: &str) -> Option<String> {
    let m = model.to_ascii_lowercase();
    let provider = m.split('/').next().unwrap_or("");
    let known = match provider {
        "anthropic" | "claude" => Some("ANTHROPIC_API_KEY"),
        "openai" | "gpt" => Some("OPENAI_API_KEY"),
        "deepseek" => Some("DEEPSEEK_API_KEY"),
        "google" | "gemini" => Some("GEMINI_API_KEY"),
        "xai" | "grok" => Some("XAI_API_KEY"),
        "mistral" => Some("MISTRAL_API_KEY"),
        "zai" | "z-ai" | "glm" => Some("ZAI_API_KEY"),
        "moonshotai" | "kimi" => Some("MOONSHOT_API_KEY"),
        "openrouter" => Some("OPENROUTER_API_KEY"),
        "vercel" | "vck" => Some("AI_GATEWAY_API_KEY"),
        "groq" => Some("GROQ_API_KEY"),
        "nvidia" | "nim" => Some("NVIDIA_API_KEY"),
        _ => None,
    };
    known.map(str::to_string).or_else(|| {
        // 通用约定：<provider> → <PROVIDER>_API_KEY。覆盖用户加进 pi models.json 的
        // 自定义网关（如 $VOLC_API_KEY / $MYGW_API_KEY）——否则凭据不注入，
        // pi 报 "No API key found for <provider>"。
        if provider.is_empty() {
            None
        } else {
            let up: String = provider
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            Some(format!("{up}_API_KEY"))
        }
    })
}

/// Which wire protocol speaks for this model + gateway. Explicit user choice
/// wins; otherwise infer from the model prefix (anthropic models talk
/// `anthropic-messages`, everything else defaults to `openai-completions`).
pub fn protocol_for(model: &str, explicit: Option<&str>) -> String {
    if let Some(api) = explicit {
        return api.to_string();
    }
    let m = model.to_ascii_lowercase();
    match m.split('/').next().unwrap_or("") {
        "anthropic" | "claude" => "anthropic-messages".to_string(),
        "google" | "gemini" => "google-generative-ai".to_string(),
        _ => "openai-completions".to_string(),
    }
}

/// Build the env overlay for one spawn: resolve which env var carries the key
/// (explicit `api_key_env` wins, else model-prefix mapping) and put the stored
/// key there. Real environment variables always win over the stored key.
pub fn spawn_env(
    model: &str,
    api_key_env: Option<&str>,
    stored_key: Option<&str>,
    base_url: Option<&str>,
    ambient: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut env = Vec::new();
    let var_name = api_key_env
        .map(str::to_string)
        .or_else(|| provider_env_for(model));
    if let (Some(var), Some(key)) = (var_name, stored_key) {
        if ambient(&var).is_none() {
            env.push((var, key.to_string()));
        }
    }
    if let Some(url) = base_url {
        // Belt and braces: models.json carries the authoritative baseUrl, but
        // protocol-standard env vars are honored by pi and by anything it
        // shells out to. Both Anthropic and OpenAI wire modes are covered.
        match protocol_for(model, None).as_str() {
            "anthropic-messages" => env.push(("ANTHROPIC_BASE_URL".to_string(), url.to_string())),
            _ => env.push(("OPENAI_BASE_URL".to_string(), url.to_string())),
        }
    }
    env
}

/// Patch `<agent-dir>/models.json` with a custom baseUrl for the model's
/// provider (pi's documented "compatible endpoint" mechanism). Additive merge:
/// existing provider config is preserved and extended.
///
/// 必须同时写入 models 数组与 apiKey 凭据引用——pi 只把「模型 id 已注册 +
/// 凭据可解析」的模型标记为 available（否则 spawn 时报 Model not found）。
pub fn patch_models_json(
    agent_dir: &Path,
    model: &str,
    base_url: &str,
    api: Option<&str>,
    api_key_env: Option<&str>,
) -> std::io::Result<()> {
    let (provider, model_id) = match model.split_once('/') {
        Some((p, id)) => (p.to_string(), id.to_string()),
        None => ("openai".to_string(), model.to_string()),
    };
    let path = agent_dir.join("models.json");
    let mut root: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(t.trim()).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if root.get("providers").is_none() {
        root["providers"] = serde_json::json!({});
    }
    let protocol = protocol_for(model, api);
    let entry = &mut root["providers"][&provider];
    if entry.is_null() {
        *entry = serde_json::json!({ "api": protocol });
    }
    // An explicit user choice of protocol always lands; otherwise only fill
    // the gap (an existing provider keeps its configured api).
    if api.is_some() || entry.get("api").is_none() {
        entry["api"] = serde_json::Value::String(protocol);
    }
    entry["baseUrl"] = serde_json::Value::String(base_url.to_string());
    // models 数组：pi 靠它解析 <provider>/<id>；已有条目保留、缺则补。
    let models = entry["models"].as_array_mut();
    let models = match models {
        Some(a) => a,
        None => {
            entry["models"] = serde_json::json!([]);
            entry["models"].as_array_mut().unwrap()
        }
    };
    if !models
        .iter()
        .any(|m| m.get("id").and_then(|x| x.as_str()) == Some(model_id.as_str()))
    {
        models.push(serde_json::json!({ "id": model_id, "name": model_id }));
    }
    // apiKey 凭据引用：自定义 provider 必须能在 models.json 里解析到凭据，
    // 否则模型保持 unavailable。约定引用 spawn 注入的环境变量（$NAME）。
    if entry.get("apiKey").is_none() {
        let var = api_key_env
            .map(str::to_string)
            .or_else(|| provider_env_for(model));
        if let Some(var) = var {
            entry["apiKey"] = serde_json::Value::String(format!("${var}"));
        }
    }
    std::fs::create_dir_all(agent_dir)?;
    std::fs::write(&path, serde_json::to_string_pretty(&root).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn provider_mapping_covers_common_prefixes() {
        assert_eq!(
            provider_env_for("openai/gpt-5.5").as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            provider_env_for("anthropic/claude-opus-4-8").as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
        assert_eq!(
            provider_env_for("zai/glm-5.2").as_deref(),
            Some("ZAI_API_KEY")
        );
    }

    #[test]
    fn custom_providers_fall_back_to_env_convention() {
        // 自定义网关（用户加进 pi models.json，key 引用 $VOLC_API_KEY 之类）
        // 必须能解析到凭据环境变量，否则 pi 报 "No API key found"。
        assert_eq!(
            provider_env_for("volc/ep-xxx").as_deref(),
            Some("VOLC_API_KEY")
        );
        assert_eq!(
            provider_env_for("my-gw/custom-model").as_deref(),
            Some("MY_GW_API_KEY")
        );
        assert_eq!(provider_env_for(""), None);
    }

    #[test]
    fn spawn_env_injects_key_without_leaking_it_into_config() {
        let env = spawn_env("zai/glm-5.2", None, Some("sk-secret"), None, &|_| None);
        assert_eq!(
            env,
            vec![("ZAI_API_KEY".to_string(), "sk-secret".to_string())]
        );

        // explicit env var name wins over the model-prefix mapping
        let env = spawn_env(
            "zai/glm-5.2",
            Some("MY_GATEWAY_KEY"),
            Some("k"),
            None,
            &|_| None,
        );
        assert_eq!(env[0].0, "MY_GATEWAY_KEY");

        // ambient env always wins — we never clobber the user's environment
        let ambient: HashMap<String, String> =
            [("ZAI_API_KEY".to_string(), "already-set".to_string())].into();
        let env = spawn_env("zai/glm-5.2", None, Some("sk-secret"), None, &|k| {
            ambient.get(k).cloned()
        });
        assert!(env.is_empty(), "must not override ambient credentials");

        // base url reaches OPENAI_BASE_URL for openai-compatible models
        let env = spawn_env(
            "openai/gpt-5.5",
            None,
            Some("k"),
            Some("https://gw/v1"),
            &|_| None,
        );
        assert!(env
            .iter()
            .any(|(k, v)| k == "OPENAI_BASE_URL" && v == "https://gw/v1"));
    }

    #[test]
    fn models_json_patch_is_additive() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("models.json"),
            r#"{"providers":{"openai":{"headers":{"x":"y"}}}}"#,
        )
        .unwrap();
        patch_models_json(dir.path(), "openai/gpt-5.5", "https://gw/v1", None, None).unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("models.json")).unwrap())
                .unwrap();
        assert_eq!(v["providers"]["openai"]["baseUrl"], "https://gw/v1");
        assert_eq!(
            v["providers"]["openai"]["headers"]["x"], "y",
            "existing config preserved"
        );
    }

    #[test]
    fn both_wire_protocols_are_supported() {
        // inference
        assert_eq!(
            protocol_for("anthropic/claude-opus-4-8", None),
            "anthropic-messages"
        );
        assert_eq!(protocol_for("openai/gpt-5.5", None), "openai-completions");
        assert_eq!(
            protocol_for("google/gemini-3", None),
            "google-generative-ai"
        );
        // explicit choice wins over inference
        assert_eq!(
            protocol_for("anthropic/claude-opus-4-8", Some("openai-completions")),
            "openai-completions"
        );

        // anthropic-protocol gateway gets an anthropic api entry + env
        let dir = TempDir::new().unwrap();
        patch_models_json(
            dir.path(),
            "anthropic/claude-opus-4-8",
            "https://gw/anthropic",
            None,
            None,
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("models.json")).unwrap())
                .unwrap();
        assert_eq!(v["providers"]["anthropic"]["api"], "anthropic-messages");
        assert_eq!(
            v["providers"]["anthropic"]["baseUrl"],
            "https://gw/anthropic"
        );

        let env = spawn_env(
            "anthropic/claude-opus-4-8",
            None,
            Some("k"),
            Some("https://gw/anthropic"),
            &|_| None,
        );
        assert!(env
            .iter()
            .any(|(k, v)| k == "ANTHROPIC_BASE_URL" && v == "https://gw/anthropic"));
        assert!(env.iter().any(|(k, _)| k == "ANTHROPIC_API_KEY"));
    }

    #[test]
    fn models_json_registers_model_id_and_credential_ref() {
        // 新用户流程实测（P0-2）：缺 models 数组或 apiKey 引用时，pi 报
        // "Model not found"（custom models remain unavailable until pi can
        // resolve credentials）。两者都必须由 patch_models_json 落盘。
        let dir = TempDir::new().unwrap();
        patch_models_json(
            dir.path(),
            "mimo/mimo-v2.6-flash",
            "https://gw/v1",
            Some("openai-completions"),
            Some("MIMO_API_KEY"),
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("models.json")).unwrap())
                .unwrap();
        let mimo = &v["providers"]["mimo"];
        assert_eq!(
            mimo["models"][0]["id"], "mimo-v2.6-flash",
            "模型 id 必须注册"
        );
        assert_eq!(
            mimo["apiKey"], "$MIMO_API_KEY",
            "凭据引用指向 spawn 注入的 env"
        );
        // 幂等：重复调用不重复注册、不覆盖已有 apiKey
        patch_models_json(
            dir.path(),
            "mimo/mimo-v2.6-flash",
            "https://gw/v1",
            None,
            Some("MIMO_API_KEY"),
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("models.json")).unwrap())
                .unwrap();
        assert_eq!(
            v["providers"]["mimo"]["models"].as_array().unwrap().len(),
            1
        );
        // 无 env 线索时按通用约定写 <PROVIDER>_API_KEY 引用（与 spawn 注入成对一致）
        let dir2 = TempDir::new().unwrap();
        patch_models_json(dir2.path(), "mystery/x-1", "https://gw/v1", None, None).unwrap();
        let v2: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir2.path().join("models.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v2["providers"]["mystery"]["models"][0]["id"], "x-1");
        assert_eq!(
            v2["providers"]["mystery"]["apiKey"].as_str(),
            Some("$MYSTERY_API_KEY"),
            "约定引用与 spawn_env 的通用回退成对一致"
        );
    }

    #[test]
    fn explicit_protocol_override_lands_in_models_json() {
        let dir = TempDir::new().unwrap();
        // openai-compatible gateway serving anthropic-style models: user says so
        patch_models_json(
            dir.path(),
            "mygw/claude-x",
            "https://gw/v1",
            Some("anthropic-messages"),
            None,
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("models.json")).unwrap())
                .unwrap();
        assert_eq!(v["providers"]["mygw"]["api"], "anthropic-messages");
    }
}
