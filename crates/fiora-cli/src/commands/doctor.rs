//! `fiora doctor` — 独立环境自检（init 的自检逻辑复用 + 更深体检）。
//! Agent 友好：`--json` 输出机器可读结果。

use crate::support::Repo;
use std::path::Path;

use fiora_processor::PiRunner;
use fiora_scanner::{opengrep, RuleRegistry};

use crate::support::dirs_fiora;

/// 一条体检项。`required` 决定退出码：必需项 ✗ → 非零退出（CI 门禁）；
/// 能力项 ✗ 只是能力关闭（如 docker 缺失 = 主动验证不跑），不判环境坏。
struct Check {
    name: &'static str,
    ok: bool,
    required: bool,
    detail: String,
}

pub(crate) fn cmd_doctor(root: &Path, json: bool) -> Result<(), String> {
    let Repo { base, .. } = Repo::open(root)?;

    let mut checks: Vec<Check> = Vec::new();

    // 环境二件套：node 硬依赖（pi 运行时），docker = 主动验证开关（能力项）
    let node = crate::support::detect_node();
    checks.push(Check {
        name: "node",
        ok: node.ok,
        required: true,
        detail: node.detail,
    });
    let docker = crate::support::detect_docker();
    checks.push(Check {
        name: "docker",
        ok: docker.ok,
        required: false,
        detail: docker.detail,
    });

    // 运行时三件套
    let pi = PiRunner::resolve(Some(&dirs_fiora().join("runtime")));
    checks.push(Check {
        name: "pi-runtime",
        ok: pi.is_some(),
        required: true,
        detail: pi
            .map(|r| r.binary().display().to_string())
            .unwrap_or_else(|| "NOT FOUND — run `fiora init`".into()),
    });
    let og = opengrep::find_binary(Some(&dirs_fiora().join("runtime")));
    checks.push(Check {
        name: "opengrep",
        ok: og.is_some(),
        required: true,
        detail: og
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "NOT FOUND — 规则通道将跳过".into()),
    });
    // 规则库与配置
    let reg = RuleRegistry::load(Some(&dirs_fiora().join("rules")), Some(&base.join("rules")));
    match reg {
        Ok(r) => checks.push(Check {
            name: "rules",
            ok: true,
            required: true,
            detail: format!("{} 条（三级加载）", r.len()),
        }),
        Err(e) => checks.push(Check {
            name: "rules",
            ok: false,
            required: true,
            detail: e.to_string(),
        }),
    }
    let cfg = crate::support::config(&base);
    checks.push(Check {
        name: "config",
        ok: true,
        required: true,
        detail: format!(
            "model={:?} thinking={} base_url={:?}",
            cfg.default_model, cfg.thinking_level, cfg.base_url
        ),
    });
    let creds = fiora_core::Credentials::load(&dirs_fiora());
    checks.push(Check {
        name: "credentials",
        ok: true,
        required: true,
        detail: if creds.api_key.is_some() {
            "已配置（~/.fiora/credentials.json，chmod 600）".into()
        } else {
            "未配置（可用环境变量 / --api-key-env）".into()
        },
    });

    // 门禁只看必需项；能力项单独归组（agents 据此决定要不要跑主动验证）。
    let required_ok = checks.iter().all(|c| !c.required || c.ok);
    let active_verify = docker.ok;
    if json {
        let items: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                serde_json::json!({"check": c.name, "ok": c.ok, "required": c.required, "detail": c.detail})
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "healthy": required_ok,
                "activeVerification": active_verify,
                "root": root,
                "checks": items,
            })
        );
    } else {
        for c in &checks {
            let mark = if c.ok { "✓" } else { "✗" };
            let tier = if c.required { "" } else { "（能力项）" };
            println!("{:<12} {}  {}{}", c.name, mark, c.detail, tier);
        }
        println!();
        if required_ok && active_verify {
            println!("doctor: 一切就绪（主动验证：可用）");
        } else if required_ok {
            println!(
                "doctor: 一切就绪（主动验证：不可用——docker 缺失时 skill 不启动动态验证，装不装由用户决定）"
            );
        } else {
            println!("doctor: 存在必需项 ✗，按提示修复后重跑");
        }
    }
    // 自检命令的退出码就是门禁信号：必需项 ✗ 必须非零退出，否则 CI 里
    // `fiora doctor && fiora run` 会带着坏环境往下跑。能力项不影响退出码。
    if required_ok {
        Ok(())
    } else {
        Err("doctor: 存在必需项 ✗（exit 1）".into())
    }
}
