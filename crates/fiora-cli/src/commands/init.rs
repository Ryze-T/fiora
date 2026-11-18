//! `fiora init` 命令组（DESIGN.md §2）。

use crate::support::Repo;
use std::fs;
use std::path::{Path, PathBuf};

use fiora_processor::PiRunner;

use crate::runtime;
use crate::support::dirs_fiora;

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_init(
    root: &Path,
    model: Option<String>,
    budget_model: Option<String>,
    thinking: Option<String>,
    api_key: Option<String>,
    api_key_env: Option<String>,
    base_url: Option<String>,
    api: Option<String>,
) -> Result<(), String> {
    let Repo { root, base, .. } = Repo::open(root)?;

    // 1. project config (model defaults — written once, used by every command)
    let mut cfg = crate::support::config(&base);
    if model.is_some() {
        cfg.default_model = model;
    }
    if budget_model.is_some() {
        cfg.budget_model = budget_model;
    }
    if let Some(t) = thinking {
        cfg.thinking_level = t;
    }
    if api_key_env.is_some() {
        cfg.api_key_env = api_key_env;
    }
    if base_url.is_some() {
        cfg.base_url = base_url;
    }
    if api.is_some() {
        cfg.api = api;
    }
    cfg.save(&base).map_err(|e| e.to_string())?;
    println!(
        "config:   .fiora/config.json (model={:?}, thinking={})",
        cfg.default_model, cfg.thinking_level
    );

    // 1b. API key -> ~/.fiora/credentials.json (chmod 600; never project/git)
    if let Some(key) = api_key {
        fiora_core::Credentials { api_key: Some(key) }
            .save(&dirs_fiora())
            .map_err(|e| e.to_string())?;
        println!(
            "creds:    ~/.fiora/credentials.json written (chmod 600, never in project config)"
        );
    }
    // 1c. custom endpoint -> pi's documented models.json mechanism (additive)
    if let (Some(model), Some(url)) = (&cfg.default_model, &cfg.base_url) {
        let agent_dir = std::env::var_os("PI_CODING_AGENT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".pi/agent"))
                    .unwrap_or_default()
            });
        let protocol = fiora_processor::protocol_for(model, cfg.api.as_deref());
        fiora_processor::patch_models_json(
            &agent_dir,
            model,
            url,
            cfg.api.as_deref(),
            cfg.api_key_env.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        println!(
            "route:    {} -> {} [{}] (models.json patched)",
            model, url, protocol
        );
    }

    // 2. INFO.md — the repository's semantic context, injected into prompts
    let info = root.join("INFO.md");
    if !info.exists() {
        fs::write(
            &info,
            "# 仓库语义理解（INFO.md）\n\n             > 此文件注入所有 AI 判定 prompt，写清业务上下文会显著提升判定质量。\n\n             ## 业务\n这个服务是：\n\n             ## 核心资产\n（用户数据 / 凭据 / 资金 / 权限 …在哪）\n\n             ## 信任边界\n（哪些入口是外部的、哪些是内部的、鉴权在哪一层）\n",
        )
        .map_err(|e| e.to_string())?;
        println!("info:     INFO.md created (fill it in — it feeds every prompt)");
    } else {
        println!("info:     INFO.md already present, kept");
    }

    // 3. rule corpus as editable files (three-level, see `fiora rules list`)
    let user_rules = dirs_fiora().join("rules");
    let sync = fiora_scanner::sync_builtin_copies(&user_rules).map_err(|e| e.to_string())?;
    if !sync.refreshed.is_empty() {
        println!(
            "rules:    {} builtin rule file(s) materialized/refreshed",
            sync.refreshed.len()
        );
    }
    for name in &sync.kept_customized {
        println!(
            "rules:    {name} kept AS EDITED (shadows the bundled corpus; delete it or `fiora rules list` to compare)"
        );
    }
    let readme = user_rules.join("README.md");
    if !readme.exists() {
        fs::write(
            &readme,
            "# Fiora Rules\n\n             三级规则目录，同 id 高级覆盖低级：\n\n             1. builtin/ —— 内置规则的可编辑副本（同 id 覆盖内置；未改动会随升级自动刷新）\n             2. 本目录 *.yaml —— 你的用户级规则\n             3. <项目>/.fiora/rules/ —— 项目级规则（随仓库 git 共享）\n\n             格式 = Semgrep YAML。校验：`fiora rules validate`；让模型按盲区起草：`fiora draft-rules`。\n",
        )
        .map_err(|e| e.to_string())?;
    }
    let project_rules = base.join("rules");
    fs::create_dir_all(&project_rules).map_err(|e| e.to_string())?;
    println!("rules:    ~/.fiora/rules/builtin/ materialized (editable), project rules dir ready");

    // 4. runtime bootstrap — pi + opengrep are installed INTO ~/.fiora/runtime
    // 环境能力自检：node 是硬依赖（pi 运行时），docker 是主动验证开关——
    // 缺哪个如实报缺，fiora 不代替用户安装任何东西。
    let node = crate::support::detect_node();
    println!(
        "env:      node:   {}  {}",
        if node.ok { "✓" } else { "✗" },
        node.detail
    );
    if !node.ok {
        println!("          （node 是 pi 运行时的硬依赖，请自行安装 Node.js ≥22）");
    }
    let docker = crate::support::detect_docker();
    println!(
        "env:      docker: {}  {}",
        if docker.ok { "✓" } else { "✗" },
        docker.detail
    );
    if !docker.ok {
        println!("          （主动验证/动态验证关闭：skill 不启动；是否安装 docker 由用户决定，fiora 不代装）");
    }
    let mut ok = true;
    for line in runtime::ensure_runtime(&dirs_fiora()) {
        if line.contains("failed") || line.contains("unavailable") {
            ok = false;
        }
        println!("runtime:  {line}");
    }
    if PiRunner::resolve(Some(&dirs_fiora().join("runtime"))).is_none() {
        ok = false;
    }

    println!();
    if ok {
        println!(
            "ready. next: fill INFO.md, then\n  fiora run --root {}",
            root.display()
        );
    } else {
        println!("setup done, but fix the runtime items above before `fiora run`.");
    }
    Ok(())
}
