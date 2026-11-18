//! fiora CLI — 入口只做三件事：解析契约（clap）、分发命令、统一错误出口。
//! 命令实现按组拆分在 `commands/` 下（开源可读性 / 二次开发友好）。
//!
//! Pipeline: scan -> evidence -> process -> chain -> report (`fiora run`)。

mod commands;
mod runtime;
mod support;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fiora",
    version,
    about = "Evidence-backed AI code audit harness"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 一键初始化：工作区 + 模型配置 + 凭据 + 规则库 + 运行时自举 + 环境自检
    Init {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 判定模型（pi 模型 id，如 openai/gpt-5.5、zai/glm-5.2）
        #[arg(long)]
        model: Option<String>,
        /// 便宜模型（triage / P2 批次用，省成本的关键档位）
        #[arg(long)]
        budget_model: Option<String>,
        /// 默认思考深度（minimal|low|medium|high|xhigh|max）
        #[arg(long)]
        thinking: Option<String>,
        /// API key——存入 ~/.fiora/credentials.json（chmod 600），spawn 时注入，不进项目配置
        #[arg(long)]
        api_key: Option<String>,
        /// 存放 key 的环境变量名（key 留在你自己的环境里，不落盘）
        #[arg(long)]
        api_key_env: Option<String>,
        /// 自定义网关端点
        #[arg(long)]
        base_url: Option<String>,
        /// 网关通信协议：openai-completions | openai-responses | anthropic-messages | google-generative-ai
        #[arg(long)]
        api: Option<String>,
    },
    /// 全流水线：scan -> evidence -> process -> chain -> report
    Run {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 运行档位（config.json profiles）：一键切换 judge/budget 模型组合
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        thinking: Option<String>,
        /// 判定并行 worker 数（批次级并行）
        #[arg(long, default_value_t = 1)]
        workers: usize,
        /// 跳过付费 AI 阶段：只跑 scan + evidence + report（零模型交付物）
        #[arg(long)]
        no_ai: bool,
        /// 书写范围：high=仅高危及以上写全契约（默认，省 token）/ all=全量全契约；判定覆盖永远全量
        #[arg(long, default_value = "high")]
        severity: String,
        /// 探索会话预算（专家覆盖：默认自动=全量覆盖）
        #[arg(long)]
        explore: Option<usize>,
    },
    /// L1：规则通道候选生成（免费、确定性）
    Scan {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// L1 通道 B：规则面之外的语义自挖掘（消耗模型预算，0day 狩猎）
    Explore {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 探索会话预算（默认按未覆盖文件量自动——无需人工选择）
        #[arg(long)]
        budget: Option<usize>,
        /// 狩猎轮数：轮 1 广扫，轮 2+ 沿线索深挖（0day 回路）
        #[arg(long, default_value_t = 1)]
        rounds: usize,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = "high")]
        thinking: String,
        /// 并发会话数（会话独立，结果单点合并）
        #[arg(long, default_value_t = 4)]
        jobs: usize,
    },
    /// L2：为全部候选预装配确定性证据骨架（免费）
    Evidence {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// L3：判定流水线 triage -> judge -> revalidate（付费阶段）
    Process {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 运行档位（config.json profiles）
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        thinking: Option<String>,
        #[arg(long)]
        budget_model: Option<String>,
        /// Parallel judge workers
        #[arg(long, default_value_t = 1)]
        workers: usize,
        /// 跳过对抗性复验轮
        #[arg(long)]
        no_revalidate: bool,
        /// 严重度范围：high=高危及以上全契约（默认）/ all=全量全契约
        #[arg(long, default_value = "high")]
        severity: String,
        /// 成本上限（美元；到达即停，可断点续跑）
        #[arg(long)]
        max_cost_usd: Option<f64>,
    },
    /// 把真阳性发现拼接成漏洞利用链
    Chain {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// 生成单文件 HTML 审计报告（离线可交付）
    Report {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// 展示范围：high=只看高危及以上（默认）/ all=全部
        #[arg(long, default_value = "high")]
        severity: String,
        /// 另存 SARIF 2.1.0 到指定路径（CI 上传/IDE 导入）
        #[arg(long)]
        sarif: Option<PathBuf>,
        /// CI 门禁：存在 >= 该严重度的发现则以退出码 1 失败（high|medium|low|all）
        #[arg(long)]
        fail_on: Option<String>,
    },
    /// 验证组：确定性差分（diff）+ Agent 验证结论回填（record）
    /// 环境启动/动态执行验证由工作台 Agent（pi/dsh）负责，不在此列
    Verify {
        #[command(subcommand)]
        cmd: VerifyCmd,
    },
    /// L5：对回归语料跑全流水线并打分（评测回归，改动必须不掉分）
    Eval {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = "high")]
        thinking: String,
        #[arg(long)]
        no_revalidate: bool,
        /// 下限门禁：只跑规则通道（确定性、零模型、CI 用）
        #[arg(long)]
        rule_only: bool,
        /// 评测的严重度范围；默认 all——评测不该继承交付口的过滤器，
        /// 否则一条被判定层正确识别的中危真阳性会被静默记成漏报
        #[arg(long, default_value = "all")]
        severity: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 生成层：按未覆盖入口起草 Semgrep 规则（人工复核后 `rules add`）
    DraftRules {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        model: Option<String>,
    },
    /// 把密实的发现文本改写成可扫读的短句分点
    Refine {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        model: Option<String>,
    },
    /// 为既有发现补影响分析 + PoC
    Enrich {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        model: Option<String>,
    },
    /// 发现文本中文化（只动展示字段，身份字段/代码/路径不动）
    Localize {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        model: Option<String>,
    },
    /// 规则库管理（三级：builtin < ~/.fiora/rules < .fiora/rules，同 id 高级覆盖低级）
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// 组合狩猎：把单点安全的发现组合成 super 漏洞（A+B 成链 / C 破保证）
    Compose {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = "xhigh")]
        thinking: String,
    },
    /// 查看发现的审计轨迹（fiora 原生呈现，不依赖外部工具）
    Trace {
        /// finding id（自动定位其判定轨迹）或直接给 trace/session id
        id: String,
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 机器可读 JSON 输出
        #[arg(long)]
        json: bool,
    },
    /// 查看模型池与档位（config.json），--json 机器可读
    Models {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// 环境自检（运行时/规则/配置/凭据），输出对 Agent 友好
    Doctor {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 机器可读 JSON 输出
        #[arg(long)]
        json: bool,
    },
    /// 项目画像：模型提取画像 + 历史 CVE 模式 + 狩猎重点（区别于 --profile 模型档位）
    Profile {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 判定同款模型（缺省用 config.json 默认模型）
        #[arg(long)]
        model: Option<String>,
        /// 已有画像时强制重提
        #[arg(long)]
        refresh: bool,
    },
    /// 账本状态快照（文件/发现/链/验证覆盖率）
    Status {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// 能力族座次表：按 RCE/SSRF/AWF 等族聚合并按可达性排序（回答“还有哪些/哪些无条件”）
    Family {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 族过滤（rce/ssrf/awf/deser/injection/authz/infoleak/dos/supplychain）
        #[arg(long)]
        family: Option<String>,
        /// 展示范围：high=只看高危及以上（默认）/ all=全部
        #[arg(long, default_value = "high")]
        severity: String,
        /// 含非 true-positive 发现（默认只看 TP）
        #[arg(long)]
        all: bool,
        /// 机器可读 JSON 输出
        #[arg(long)]
        json: bool,
    },
    /// trigger-prove 实验室脚手架（真代码 + 桩化 + canary + 正控 + 即用即毁）
    Lab {
        #[command(subcommand)]
        cmd: LabCmd,
    },
}

#[derive(Subcommand)]
enum VerifyCmd {
    /// 确定性差分：pre/post git 修订（或工作树 fix-check）上的 shape 对照
    Diff {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Pre-patch git revision（与 --post 同时给 = 差分复现）
        #[arg(long)]
        pre: Option<String>,
        /// Post-patch git revision
        #[arg(long)]
        post: Option<String>,
        /// 只验一条 finding
        #[arg(long)]
        finding: Option<String>,
    },
    /// Agent 验证结论回填（live-prove|trigger-prove|code-proof|disproved）
    Record {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// finding id
        #[arg(long)]
        finding: String,
        /// 验证等级：live-prove | trigger-prove | code-proof | disproved
        #[arg(long)]
        level: String,
        /// 证据/备注（Agent 的实测记录引用）
        #[arg(long)]
        note: Option<String>,
        /// 按验证结论校正严重度（复验常推翻判定层的初判级）
        #[arg(long)]
        severity: Option<String>,
    },
}

#[derive(Subcommand)]
enum LabCmd {
    /// 生成实验室目录（README 纪律 + Dockerfile + 桩加载器 + lab.py + run.sh）
    Scaffold {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// 按发现 id 自动填模板（sink/文件/slug）
        #[arg(long)]
        finding: Option<String>,
        /// 手动指定 sink 符号（无 --finding 时）
        #[arg(long)]
        sink: Option<String>,
        /// 手动指定源文件（相对仓库根）
        #[arg(long)]
        file: Option<String>,
        /// 输出目录（默认 <root>/labs/<slug>-lab）
        #[arg(long)]
        out: Option<PathBuf>,
        /// 目标语言（python|java|go|node）
        #[arg(long, default_value = "python")]
        lang: String,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// List the loaded rule corpus (builtin < user < project)
    List {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// Add a rule file to the user/project corpus (validated first)
    Add {
        file: PathBuf,
        /// 放入项目级目录（<root>/.fiora/rules），默认用户级
        #[arg(long)]
        project: bool,
    },
    /// Validate rule files (structure + id contract)
    Validate { file: Option<PathBuf> },
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::Init {
            root,
            model,
            budget_model,
            thinking,
            api_key,
            api_key_env,
            base_url,
            api,
        } => commands::init::cmd_init(
            &root,
            model,
            budget_model,
            thinking,
            api_key,
            api_key_env,
            base_url,
            api,
        ),
        Cmd::Run {
            root,
            profile,
            model,
            thinking,
            workers,
            no_ai,
            severity,
            explore,
        } => commands::pipeline::cmd_run(
            &root,
            profile.as_deref(),
            model,
            thinking.as_deref(),
            workers,
            no_ai,
            &severity,
            explore,
        ),
        Cmd::Compose {
            root,
            model,
            thinking,
        } => commands::compose::cmd_compose(&root, model, &thinking).map(|_| ()),
        Cmd::Scan { root } => commands::pipeline::cmd_scan(&root),
        Cmd::Explore {
            root,
            budget,
            rounds,
            model,
            thinking,
            jobs,
        } => commands::agent::cmd_explore(&root, budget, rounds, model, &thinking, jobs),
        Cmd::Evidence { root } => commands::pipeline::cmd_evidence(&root),
        Cmd::Process {
            root,
            profile,
            model,
            thinking,
            budget_model,
            workers,
            no_revalidate,
            severity,
            max_cost_usd,
        } => commands::pipeline::cmd_process(
            &root,
            profile.as_deref(),
            model,
            thinking.as_deref(),
            budget_model,
            workers,
            !no_revalidate,
            max_cost_usd,
            &severity,
        ),
        Cmd::Chain { root } => commands::pipeline::cmd_chain(&root),
        Cmd::DraftRules { root, model } => commands::agent::cmd_draft_rules(&root, model),
        Cmd::Localize { root, model } => commands::agent::cmd_localize(&root, model),
        Cmd::Enrich { root, model } => commands::agent::cmd_enrich(&root, model),
        Cmd::Refine { root, model } => commands::agent::cmd_refine(&root, model),
        Cmd::Verify { cmd } => match cmd {
            VerifyCmd::Diff {
                root,
                pre,
                post,
                finding,
            } => commands::verify::cmd_verify(
                &root,
                pre.as_deref(),
                post.as_deref(),
                finding.as_deref(),
            ),
            VerifyCmd::Record {
                root,
                finding,
                level,
                note,
                severity,
            } => commands::verify::cmd_verify_record(
                &root,
                &finding,
                &level,
                note.as_deref(),
                severity.as_deref(),
            ),
        },
        Cmd::Eval {
            corpus,
            model,
            thinking,
            no_revalidate,
            rule_only,
            severity,
            out,
        } => commands::eval::cmd_eval(
            &corpus,
            model,
            &thinking,
            !no_revalidate,
            rule_only,
            &severity,
            out.as_deref(),
        ),
        Cmd::Report {
            root,
            out,
            severity,
            sarif,
            fail_on,
        } => commands::report::cmd_report(
            &root,
            out.as_deref(),
            &severity,
            sarif.as_deref(),
            fail_on.as_deref(),
        ),
        Cmd::Trace { id, root, json } => commands::trace::cmd_trace(&root, &id, json),
        Cmd::Models { root, json } => commands::status::cmd_models(&root, json),
        Cmd::Doctor { root, json } => commands::doctor::cmd_doctor(&root, json),
        Cmd::Rules { cmd } => match cmd {
            RulesCmd::List { root } => commands::rules::cmd_rules_list(&root),
            RulesCmd::Add { file, project } => {
                let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                commands::rules::cmd_rules_add(&file, project, &cwd)
            }
            RulesCmd::Validate { file } => commands::rules::cmd_rules_validate(file.as_deref()),
        },
        Cmd::Profile {
            root,
            model,
            refresh,
        } => commands::agent::cmd_profile(&root, model, refresh),
        Cmd::Status { root } => commands::status::cmd_status(&root),
        Cmd::Family {
            root,
            family,
            severity,
            all,
            json,
        } => commands::family::cmd_family(&root, family, &severity, all, json),
        Cmd::Lab { cmd } => match cmd {
            LabCmd::Scaffold {
                root,
                finding,
                sink,
                file,
                out,
                lang,
            } => commands::lab::cmd_lab_scaffold(&root, finding, sink, file, out, &lang),
        },
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ---------- pipeline stages ----------
