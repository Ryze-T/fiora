//! Prompt assembly (DESIGN.md §5) — all prompts are runtime data (P8):
//! built-in defaults can be overridden or extended from `<fiora_home>/prompts/`.

use std::fs;
use std::path::Path;

/// Load a prompt override from the prompts dir; fall back to the built-in text.
pub fn load_or_default(prompts_dir: Option<&Path>, name: &str, builtin: &str) -> String {
    if let Some(dir) = prompts_dir {
        for ext in ["md", "txt"] {
            let p = dir.join(format!("{name}.{ext}"));
            if let Ok(text) = fs::read_to_string(&p) {
                return text;
            }
        }
    }
    builtin.to_string()
}

/// Channel B semantic self-mining prompt (DESIGN.md §3).
///
/// The agent explores code OUTSIDE covered paths — the rule channel already
/// swept the covered surface. Its mission: the things rules can never see
/// (semantic anomalies, suppressed alerts, auth-shaped skips, backdoors).
pub const SEMANTIC_EXPLORE_BUILTIN: &str = include_str!("../assets/prompts/semantic-explore.md");

/// Ask the agent to complete an incomplete JSON output (single repair attempt).
///
/// **必须携带原始任务**：修复请求是一个新会话，只给「投诉+旧回复」会让 agent
/// 无上下文返回 `[]`，静默吞掉整批判定（kubeadmiral 压力测试实证）。
pub fn json_repair_prompt(original_task: &str, bad: &str) -> String {
    // 只说「不是合法 JSON」时模型会原样重发同一份错位输出，一次修复机会白扔。
    // 解析器原话（出错行列 + 原因）能指出到底哪个字符坏了，这里就地取。
    let parser_says = serde_json::from_str::<serde_json::Value>(crate::verdict::extract_json(bad))
        .err()
        .map(|e| {
            format!(
                "The parser rejected it with:\n{e}\n\nThat message names the exact place \
                 it stopped — an unbalanced brace, a stray comma, or an unescaped quote \
                 inside a string. Fix that spot.\n"
            )
        })
        .unwrap_or_else(|| {
            "It parsed as JSON but matched none of the accepted shapes — check the object \
             keys against the schema above.\n"
                .to_string()
        });
    format!(
        "{original_task}\n\n---\nYour previous reply was not usable. {parser_says}\n\
         Complete the task above and reply with ONLY the JSON value matching the \
         schema requested in the task above — one value, no fences, no commentary.\
         \n\nPrevious reply:\n{}",
        bad.chars().take(4000).collect::<String>()
    )
}

/// 契约修复提示：上一次回复是**合法 JSON**，但违反判定契约（真阳性缺 impact /
/// 缺 PoC / 身份锚点为空 / rebuttal 未确认…）。与「不是 JSON」的修复不同，这里必须
/// 把具体违规点喂回去，否则模型会原样重发同一份输出。
pub fn contract_repair_prompt(original_task: &str, violation: &str, bad: &str) -> String {
    format!(
        "{original_task}\n\n---\nYour previous reply WAS valid JSON but violated the audit \
         contract:\n{violation}\n\nRe-emit the SAME findings with the same conclusions, \
         fixing only what the violation names. Every `true-positive` must carry: a non-empty \
         `impact` (concrete consequence + why the severity holds), a `repro_pack` whose \
         `request`/`expected`/`actual` are filled, a non-empty `sink_symbol` and \
         `enclosing_fn`, `evidence.entries` plus `evidence.call_chain`, and \
         `verdict.rebuttals.reachable: true`. If a finding cannot honestly satisfy that, \
         lower its conclusion to `uncertain` instead of leaving fields empty. Reply with ONLY \
         the JSON value, no fences, no commentary.\n\nPrevious reply:\n{}",
        bad.chars().take(6000).collect::<String>()
    )
}

/// 狩猎规划（plan/execute 分离）：一次会话产出全仓假设清单——
/// 执行会话按假设分工，广度可控、深度可并行、假设可复用。
pub fn hunt_plan_prompt(
    tech: &[String],
    surface_summary: &str,
    uncovered: &[String],
    hunt_memo: Option<&str>,
) -> String {
    format!(
        include_str!("../assets/prompts/hunt-plan.md"),
        highlights = with_memo(tech_highlights(tech), hunt_memo),
        surface = if surface_summary.trim().is_empty() {
            "(none provided — hypothesize from the file list)"
        } else {
            surface_summary
        },
        files = uncovered
            .iter()
            .take(300)
            .map(|m| format!("- {m}\n"))
            .collect::<String>(),
    )
}

/// Per-tech threat highlights (DESIGN.md §5): injected when the tech stack is
/// detected. This is the distilled framework trap knowledge.
/// 把模型画像块接到 highlights 尾部（无画像 = 原样）。
pub fn with_memo(base: String, hunt_memo: Option<&str>) -> String {
    match hunt_memo {
        Some(m) if !m.trim().is_empty() => format!("{base}\n{m}\n"),
        _ => base,
    }
}

pub fn tech_highlights(tags: &[String]) -> String {
    let mut out = String::new();
    let add = |out: &mut String, title: &str, body: &str| {
        out.push_str(&format!("\n### {title}\n{body}\n"));
    };
    for t in tags {
        match t.as_str() {
            "nextjs" => add(&mut out, "Next.js",
                "- middleware.ts is NOT sufficient auth: handlers must check auth themselves\n\
                 - Server Actions are public POST endpoints\n\
                 - JSON embedded in <script> needs XSS escaping; search params are untrusted\n\
                 - cache tags can leak across tenants"),
            "express" | "koa" | "hono" | "fastify" => add(&mut out, "Node frameworks",
                "- route vs middleware ordering decides auth; a middleware registered after the route never runs\n\
                 - express.static / sendFile path traversal; error responses can leak internals\n\
                 - CORS reflect = credential theft"),
            "gin" | "echo" | "fiber" | "chi" | "gorilla" => add(&mut out, "Go HTTP frameworks",
                "- group middleware applies only to routes registered after the group was created\n\
                 - c.Query/c.Param values flow into fmt.Sprintf SQL = injection\n\
                 - c.File()/Static path traversal"),
            "django" | "flask" | "fastapi" | "tornado" | "starlette" => add(&mut out, "Python frameworks",
                "- Django: mark_safe / |safe bypasses auto-escaping; raw() and extra() are injection sinks\n\
                 - Flask/Jinja: |safe and Markup; FastAPI: Depends() is the auth boundary — endpoints without it are public\n\
                 - open redirects via next= parameters"),
            "kubernetes" => add(&mut out, "Kubernetes 控制面/多集群",
                "- CRD spec 字段若直驱 client 构造/网络/凭据消费 = 集群冒充与 SSRF（先核 RBAC 谁能建该 CRD）\n\
                 - 控制面读取 Secret（kubeconfig/token/证书）是信任根：读取面、外发面、日志回显都要追\n\
                 - admission webhook：TLS 校验跳过、CA 注入、failurePolicy=Ignore 绕过、webhook 逻辑直接信 request 内容\n\
                 - 传播策略（PropagationPolicy/Override）：低权用户可控模板字段（privileged/hostPath/SA）扩散到成员集群 = 容器接管\n\
                 - aggregated apiserver/聚合代理：impersonation、用系统凭据代成员集群读数据 = 跨集群越权\n\
                 - remotecommand/pod exec/attach = 容器内 shell；目标 pod/namespace 可控即接管\n\
                 - informer 缓存键来自队列 key 时非 IDOR；但来自用户请求的对象名/命名空间要核越权\n\
                 - pprof/metrics/healthz 调试端口默认 0.0.0.0 = 未鉴权信息面"),
            "serialization" | "protobuf" => add(&mut out, "序列化/编解码",
                "- 反序列化入口（pickle/marshal/yaml.load/ObjectInputStream/XStream/Fastjson autoType/Jackson enableDefaultTyping）= RCE 面\n\
                 - Protobuf/Thrift 生成代码之外的手工解析、Any 类型展开、动态消息 = 注入面\n\
                 - 二次序列化：对象落库后再读回的路径常绕过入口校验"),
            "jwt" => add(&mut out, "认证/令牌框架",
                "- JWT: alg=none / 密钥混淆(RS256→HS256) / kid 注入 / 过期与签发校验缺失\n\
                 - OAuth: redirect_uri 未锚定、state 缺失、code 重放\n\
                 - Session: 固定会话、cookie 属性缺失、登出不吊销\n\
                 - 权限注解/中间件的顺序问题（先路由后鉴权）"),
            "kafka" | "taskqueue" | "redis" | "mongodb" => add(&mut out, "消息队列/缓存/NoSQL",
                "- 消费者反序列化消息体（pickle/JSON 多态）= 可投毒入口\n\
                 - Redis/Mongo 查询构造：拼接 key/查询条件 = 注入；未鉴权实例 = 直通\n\
                 - 队列 topic/组权限：谁能投递=谁能触发消费端逻辑\n\
                 - 任务队列（celery 等）：任务参数反序列化、task 注册表滥用"),
            "cloudsdk" => add(&mut out, "云 SDK/对象存储",
                "- 预签名 URL 生成：过期/范围/Content-Type 约束缺失\n\
                 - 凭据链：环境变量/元数据服务(IMDS)暴露面、临时凭据转发\n\
                 - 路径与桶名来自用户输入 = 越权读写（SSRF 变体）\n\
                 - 回调/事件通知 URL 可控 = SSRF"),
            "grpc" => add(&mut out, "RPC/服务间调用",
                "- 拦截器链的鉴权覆盖（哪些方法裸奔）\n\
                 - 元数据(header)透传：用户可控身份头直达下游 = 冒充\n\
                 - 流式接口的输入校验弱于一元接口\n\
                 - 反射服务/健康检查暴露"),
            "xml" => add(&mut out, "XML 处理",
                "- XXE: DocumentBuilder/SAXParser/lxml 未禁外部实体\n\
                 - XSLT 注入、XPath 注入、XML 签名包装攻击（signature wrapping）"),
            "spring" | "micronaut" => add(&mut out, "JVM frameworks",
                "- @RequestMapping without auth annotation = public endpoint (class-level annotations are easy to forget)\n\
                 - SpEL injection in @Value; mass assignment via @RequestBody binding\n\
                 - actuator endpoints exposure"),
            _ => {}
        }
    }
    out
}

/// Judge prompt — the core protocol (DESIGN.md §5). Everything the agent is
/// given here is either deterministic evidence or runtime data.
pub fn judge_prompt(
    info_md: &str,
    tech_tags: &[String],
    batch_context: &str,
    severity_scope: &str,
    hunt_memo: Option<&str>,
) -> String {
    // 严重度范围是唯一的资源调节阀（深度永远全量）：
    //   high —— 高危及以上全契约（impact/preconditions/repro/证据链），其余精简一行
    //   all  —— 全部全契约
    let scope_note = if severity_scope == "high" {
        "\n## Severity scope: HIGH+ ONLY\n         This audit only invests full-contract effort in HIGH and CRITICAL findings.\n         For anything you would rate MEDIUM or below (incl. non-security bugs): emit it with\n         minimal fields only — slug, category, title, severity, file, line, sink_symbol,\n         enclosing_fn, description (one line), verdict — and leave impact/preconditions/\n         repro_pack/data_flow empty. Do NOT drop them silently (every candidate reaches a\n         verdict), but do not spend tokens writing them up either.\n"
    } else {
        ""
    };
    format!(
        include_str!("../assets/prompts/judge.md"),
        highlights = with_memo(tech_highlights(tech_tags), hunt_memo),
        info_md = if info_md.trim().is_empty() {
            "(none)"
        } else {
            info_md
        },
        batch_context = batch_context,
        scope_note = scope_note,
    )
}

/// Revalidation prompt — adversarial second pass (DESIGN.md §5).
pub fn revalidate_prompt(finding_json: &str) -> String {
    format!(
        include_str!("../assets/prompts/revalidate.md"),
        finding_json = finding_json
    )
}

/// Triage prompt — cheap first pass over candidate text only (DESIGN.md §5).
pub fn triage_prompt(candidates_blob: &str) -> String {
    format!(
        include_str!("../assets/prompts/triage.md"),
        candidates_blob = candidates_blob
    )
}

/// Rule-drafting prompt (`fiora rules draft`): the model writes ordinary Fiora
/// Rules YAML for the uncovered entry points. Drafts go through the SAME
/// three-level registry validation as hand-written rules — there is no second
/// matcher language, and nothing is compiled from model output.
pub fn rule_draft_prompt(gaps: &str, tech: &str) -> String {
    format!(
        include_str!("../assets/prompts/rule-draft.md"),
        gaps = gaps,
        tech = tech
    )
}

/// Localization prompt: rewrite finding texts into Chinese without touching
/// identity, code or paths. Used by `fiora localize` on existing ledgers.
pub fn localize_prompt(items_json: &str) -> String {
    format!(
        include_str!("../assets/prompts/localize.md"),
        items_json = items_json
    )
}

/// Enrich prompt: backfill impact analysis + PoC (repro pack) for existing
/// findings so every finding is assessable and reproducible.
pub fn enrich_prompt(items_json: &str) -> String {
    format!(
        include_str!("../assets/prompts/enrich.md"),
        items_json = items_json
    )
}

/// Refine prompt: rewrite dense prose into short-sentence, point-form Chinese
/// so findings are scannable. Facts and conclusions unchanged.
pub fn refine_prompt(items_json: &str) -> String {
    format!(
        include_str!("../assets/prompts/refine.md"),
        items_json = items_json
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_tags_still_pull_their_playbooks() {
        // 画像改由模型提取后，框架级（依赖识别）playbook 仍是确定性下限。
        let tags = vec!["express".to_string()];
        let h = tech_highlights(&tags);
        assert!(h.contains("Node frameworks"), "{h}");
        let tags = vec!["spring".to_string()];
        assert!(tech_highlights(&tags).contains("JVM frameworks"));
    }

    #[test]
    fn hunt_memo_is_appended_to_highlights() {
        let memo = "### 项目画像与狩猎重点（模型提取 · 仅注意力引导，不作证据）\n- 狩猎优先级：\n  1. 权重热更接口 —— 管理面未鉴权";
        let s = with_memo(tech_highlights(&[]), Some(memo));
        assert!(s.contains("项目画像与狩猎重点"));
        assert!(s.contains("权重热更接口"));
        // 无画像 = 原样
        assert_eq!(with_memo("x".into(), None), "x");
    }
}
