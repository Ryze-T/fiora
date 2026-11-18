//! 命令组共享支撑（仓库/账本定位 / 思考档解析 / 成本汇总）。
//!
//! 每个子命令的第一步都是同一件事：规范化 root、定位 `.fiora`、打开账本。
//! 三行样板原本散落 20 处，这里只留一份实现——顺便让所有命令的失败文案一致。

use std::fs;
use std::path::{Path, PathBuf};

use fiora_core::{Finding, Ledger, ProjectConfig, RunMeta};
use fiora_processor::{PiRunner, ThinkingLevel};
use fiora_scanner::SurfaceEntry;

/// 已打开账本的仓库上下文。
pub(crate) struct Repo {
    pub root: PathBuf,
    pub base: PathBuf,
    pub ledger: Ledger,
}

impl Repo {
    pub fn open(root: &Path) -> Result<Repo, String> {
        let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;
        let base = root.join(".fiora");
        let ledger = Ledger::open(&base).map_err(|e| format!("ledger: {e}"))?;
        Ok(Repo { root, base, ledger })
    }
}

/// 账本里全部已落账发现（未做严重度过滤——过滤是各视图自己的事）。
pub(crate) fn findings(ledger: &Ledger) -> Result<Vec<Finding>, String> {
    let mut out = Vec::new();
    for fid in ledger.list_finding_ids().map_err(|e| e.to_string())? {
        if let Some(f) = ledger.load_finding(&fid).map_err(|e| e.to_string())? {
            out.push(f);
        }
    }
    Ok(out)
}

/// 入口面清单（scan 阶段产物）；缺失或损坏时为空——调用方不必关心 IO 错误。
pub(crate) fn surface(base: &Path) -> Vec<SurfaceEntry> {
    fs::read_to_string(base.join("surface.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub(crate) fn config(base: &Path) -> ProjectConfig {
    ProjectConfig::load(base)
}

/// 账本数据目录下的 JSON 产物（tech.json / surface.json / …）。
pub(crate) fn write_json<T: serde::Serialize>(
    base: &Path,
    name: &str,
    value: &T,
) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(base.join(name), text).map_err(|e| e.to_string())
}

pub(crate) fn run_totals(ledger: &Ledger) -> Result<(f64, u64), String> {
    let mut usd = 0.0;
    let mut tokens = 0u64;
    for entry in fs::read_dir(ledger.base_dir().join("runs")).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "json") {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<RunMeta>(&text) {
                    usd += meta.cost.usd;
                    tokens += meta.cost.tokens_in + meta.cost.tokens_out;
                }
            }
        }
    }
    Ok((usd, tokens))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_thinking(s: &str) -> Result<ThinkingLevel, String> {
    Ok(match s {
        "off" => ThinkingLevel::Off,
        "minimal" => ThinkingLevel::Minimal,
        "low" => ThinkingLevel::Low,
        "medium" => ThinkingLevel::Medium,
        "high" => ThinkingLevel::High,
        "xhigh" => ThinkingLevel::Xhigh,
        "max" => ThinkingLevel::Max,
        other => return Err(format!("unknown thinking level: {other}")),
    })
}

/// 严重度范围校验（CLI 入口统一口径，避免 "medium" 被当成"未知即高危"）。
pub(crate) fn validate_severity(s: &str) -> Result<(), String> {
    if fiora_core::family::severity_threshold(s).is_some() {
        Ok(())
    } else {
        Err(format!(
            "unknown severity: {s}（可用：all | info | low | medium | high | critical）"
        ))
    }
}

pub(crate) fn dirs_fiora() -> PathBuf {
    std::env::var_os("FIORA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".fiora"))
                .unwrap_or_else(|| PathBuf::from(".fiora"))
        })
}

/// 单点模型运行时装配（pi 二进制 + 凭据注入）——所有 spawn 模型会话的
/// 命令都必须走这里。
///
/// 此前只有判定通道注入凭据（spawn_env → with_env），explore / compose /
/// draft-rules / refine / enrich / localize 全部裸 spawn：key 只存在 fiora
/// 凭据库时（`init --api-key` 的正常安装形态）pi 直接报「No API key found
/// for <provider>」退出，六个通道整体静默空转，还会把空输出读成「无发现」。
///
/// `override_model`（CLI --model）与配置默认模型都会注入：单次覆盖换成
/// 另一个 provider 的模型时，默认模型的 key 仍然可解析，不会制造新坑。
pub(crate) fn model_runner(base: &Path, override_model: Option<&str>) -> Result<PiRunner, String> {
    let proj = config(base);
    let creds = fiora_core::Credentials::load(&dirs_fiora());
    let runner = PiRunner::resolve(Some(&dirs_fiora().join("runtime")))
        .ok_or_else(|| "pi binary not found (set FIORA_PI_BIN)".to_string())?;
    let ambient = |k: &str| std::env::var(k).ok();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut models: Vec<&str> = Vec::new();
    if let Some(m) = override_model {
        models.push(m);
    }
    if let Some(m) = proj.default_model.as_deref() {
        models.push(m);
    }
    for m in models {
        for (k, v) in fiora_processor::spawn_env(
            m,
            proj.api_key_env.as_deref(),
            creds.api_key.as_deref(),
            proj.base_url.as_deref(),
            &ambient,
        ) {
            // 同名变量先到先得：先注入的是本次会话真正要用的模型。
            if !env.iter().any(|(ek, _)| *ek == k) {
                env.push((k, v));
            }
        }
    }
    Ok(runner.with_env(env))
}

/// 环境能力探测：node 是 pi 运行时的硬依赖（required），docker 是主动验证
/// （动态部署/canary）的能力开关（capability）——fiora 不代装任何东西，
/// 探测结果只用来决定「跑不跑主动验证」，缺了就诚实标注缺。
pub(crate) struct EnvCap {
    pub ok: bool,
    pub detail: String,
}

pub(crate) fn detect_node() -> EnvCap {
    match std::process::Command::new("node").arg("--version").output() {
        Ok(o) if o.status.success() => EnvCap {
            ok: true,
            detail: String::from_utf8_lossy(&o.stdout).trim().to_string(),
        },
        Ok(_) => EnvCap {
            ok: false,
            detail: "node 不可执行".to_string(),
        },
        Err(_) => EnvCap {
            ok: false,
            detail: "未安装（pi 运行时的硬依赖）".to_string(),
        },
    }
}

pub(crate) fn detect_docker() -> EnvCap {
    // 客户端在但 daemon 不可达 = 能力仍不可用（只报「已装」会误导主动验证）。
    // 很多机器 docker 需 sudo：`sudo -n`（非交互，绝不弹密码、绝不代装）兜底，
    // 能用就如实标「需 sudo」，skill 侧用 sudo docker 起实验环境。
    let version = std::process::Command::new("docker")
        .arg("--version")
        .output();
    match version {
        Ok(o) if o.status.success() => {
            let ver = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let daemon = std::process::Command::new("docker")
                .args(["info", "--format", "{{.ServerVersion}}"])
                .output();
            if let Ok(d) = daemon {
                if d.status.success() {
                    return EnvCap {
                        ok: true,
                        detail: format!(
                            "{ver}（daemon {}）",
                            String::from_utf8_lossy(&d.stdout).trim()
                        ),
                    };
                }
            }
            let sudo_daemon = std::process::Command::new("sudo")
                .args(["-n", "docker", "info", "--format", "{{.ServerVersion}}"])
                .output();
            match sudo_daemon {
                Ok(d) if d.status.success() => EnvCap {
                    ok: true,
                    detail: format!(
                        "{ver}（daemon {}，需 sudo——skill 起实验用 sudo docker）",
                        String::from_utf8_lossy(&d.stdout).trim()
                    ),
                },
                _ => EnvCap {
                    ok: false,
                    detail: "已安装但 daemon 不可达（主动验证不可用）".to_string(),
                },
            }
        }
        _ => EnvCap {
            ok: false,
            detail: "未安装（主动验证/动态验证不可用；装不装由用户决定，fiora 不代装）".to_string(),
        },
    }
}

/// 模型画像注入块（`.fiora/profile.json` → 渲染）。缺文件/坏文件 = 无画像，
/// 各会话照常跑（画像只是注意力引导）。
pub(crate) fn hunt_memo(base: &Path) -> Option<String> {
    let text = std::fs::read_to_string(base.join("profile.json")).ok()?;
    let profile: fiora_processor::ProjProfile = serde_json::from_str(&text).ok()?;
    Some(fiora_processor::render_hunt_memo(&profile))
}
