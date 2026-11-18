//! `fiora-report` — 单文件审计报告渲染器（版式契约 = 用户模板
//! `代码审计报告模板.html`，见 docs/REPORT-TEMPLATE.md）。
//!
//! 暗色主题 + 左侧目录 + 自动统计 JS + mermaid 攻击链 + 发现↔PoC 双向跳转。
//! 数据全部由 ReportData 绑定；统计卡/分布条/环形图/目录由模板 JS 扫描
//! `.finding[data-sev]` 自动生成——渲染器只负责把数据变成卡片。

use std::collections::HashMap;

use fiora_core::{Chain, Evidence, Finding, Severity, VerdictConclusion};

pub mod checklist;
pub mod sarif;
pub use checklist::{build_checklist, render_json, VerifyTask};
pub use sarif::render_sarif;

const TEMPLATE_CSS: &str = include_str!("template.css");
const TEMPLATE_JS: &str = include_str!("template.js");
/// Mermaid 10.9.1 (MIT) vendored inline — the report must open offline with
/// zero external resources. Only embedded when the report actually contains
/// diagrams, so diagram-free reports stay small.
const MERMAID_JS: &str = include_str!("vendor/mermaid-10.9.1.min.js");
/// Marker identifying the vendored mermaid build inside rendered HTML.
pub const MERMAID_TAG: &str = "(function(JM,Ag){typeof exports";

// ---------- input ----------

pub struct SurfaceRow {
    pub file: String,
    pub line: u32,
    pub symbol: String,
    pub route: Option<String>,
    pub status: String,
}

pub struct Coverage {
    pub files_tracked: usize,
    pub files_analyzed: usize,
    pub files_skipped: usize,
    pub files_pending: usize,
    pub candidates_rule: usize,
    pub candidates_semantic: usize,
    pub surface_entries: usize,
}

pub struct ReportData {
    pub project: String,
    pub repo_label: String,
    pub method: String,
    pub agent_label: String,
    pub generated_at: String,
    pub scope: String,
    pub tech_tags: Vec<String>,
    pub findings: Vec<Finding>,
    pub chains: Vec<Chain>,
    pub evidence: Vec<Evidence>,
    /// finding id -> annotated source snippet (line-numbered)
    pub snippets: HashMap<String, String>,
    pub coverage: Coverage,
    pub surface: Vec<SurfaceRow>,
    pub method_notes: Vec<String>,
    pub cost_summary: Option<String>,
}

// ---------- RCE 提取规则（docs/REPORT-TEMPLATE.md） ----------

/// 执行/反序列化原语（sink 级识别——RCE 章的准入线）。
const EXEC_SINK_MARKERS: &[&str] = &[
    "eval(",
    "exec(",
    "system(",
    "compile(",
    "pickle.load",
    "marshal.load",
    "unserialize",
    "deserialize",
    "from_bytes",
    "render_template_string",
    "run_script",
    "script",
];

/// RCE 章准入：只认**执行面事实**，不认 impact 里的升级推测。
///
/// 判定线（三选一）：① 类别是执行/反序列化类；② sink 是执行/反序列化原语；
/// ③ title 显式声称 RCE/命令执行。impact 写"可能导致代码执行"不算——
/// 那是链路推测，应在各自的链路卡里呈现，不冒充 RCE 发现（实战教训：
/// netbox 审计 7 条越权/SSRF/泄露因 impact 含"代码执行"被塞进 RCE 章）。
pub fn is_rce(f: &Finding) -> bool {
    if matches!(
        f.category.as_str(),
        "rce" | "code-injection" | "insecure-deserialization" | "cmdi"
    ) {
        return true;
    }
    let sink = f.sink_symbol.to_ascii_lowercase();
    if EXEC_SINK_MARKERS.iter().any(|k| sink.contains(k)) {
        return true;
    }
    [
        "rce",
        "代码执行",
        "命令执行",
        "任意代码",
        "执行任意",
        "getshell",
    ]
    .iter()
    .any(|k| fiora_core::util::contains_word(&f.title, k))
}

fn is_fp(f: &Finding) -> bool {
    f.verdict.as_ref().map(|v| v.conclusion) == Some(VerdictConclusion::FalsePositive)
}

// ---------- render ----------

/// 分区：RCE 区（真 RCE 且非 FP）/ 其余区（含 FP 轻卡片）；均按严重度降序。
pub fn partition_findings(d: &ReportData) -> (Vec<&Finding>, Vec<&Finding>, Vec<&Finding>) {
    let mut ordered: Vec<&Finding> = d.findings.iter().filter(|f| !is_fp(f)).collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    let (rce, other): (Vec<&Finding>, Vec<&Finding>) = ordered.iter().partition(|f| is_rce(f));
    let mut fps: Vec<&Finding> = d.findings.iter().filter(|f| is_fp(f)).collect();
    fps.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    (rce, other, fps)
}

/// 独立攻击链卡（模板语义：真链用 mermaid 表达，不罗列两两组合；最多 5 条）。
fn chain_cards(d: &ReportData) -> String {
    let mut chain_html = String::new();
    for (i, c) in d.chains.iter().take(5).enumerate() {
        let steps: Vec<String> = c
            .steps
            .iter()
            .filter_map(|st| d.findings.iter().find(|f| f.id == st.finding_id))
            .map(|f| f.title.clone())
            .collect();
        if steps.len() < 2 {
            continue;
        }
        let ids: Vec<String> = (0..steps.len()).map(|j| format!("C{i}_{j}")).collect();
        let mut m = String::from("flowchart LR\n");
        for (j, id) in ids.iter().enumerate() {
            m.push_str(&mermaid_node(id, &steps[j]));
            if j > 0 {
                m.push_str(&mermaid_edge(&ids[j - 1], id));
            }
        }
        chain_html.push_str(&format!(
            "<div class=\"poc-card\" id=\"chain-{n}\"><div class=\"poc-head\"><div class=\"ttl\">⛓ 攻击链-{n} — {title}</div></div>\
             {flow}\
             <div style=\"margin-top:8px;\"><b>影响</b>：{impact}</div></div>",
            n = i + 1,
            title = esc(&c.title),
            flow = mermaid_block(&m),
            impact = esc(&c.impact),
        ));
    }
    chain_html
}

pub fn render_html(d: &ReportData) -> String {
    let (rce, other, fps) = partition_findings(d);

    let ev_map: HashMap<String, &Evidence> = {
        let mut m = HashMap::new();
        for e in &d.evidence {
            m.insert(e.id.clone(), e);
        }
        m
    };
    let mut rce_html = track_cards(&rce, 0, &ev_map, "rce");
    if rce.is_empty() {
        rce_html.push_str(
            "<div class=\"card\"><p>本次审计未发现可独立构成代码执行、或作为 RCE 链关键一跳的发现。\
             （诚实声明：impact 中的升级推测不计入本章——RCE 定性只认执行面事实。）</p></div>",
        );
    }
    // 其余区 = 真阳性卡 + 负向结论的轻卡片（问题/判定 两栏），编号连续
    let mut other_html = track_cards(&other, rce.len(), &ev_map, "other");
    let fp_base = rce.len() + other.len();
    for (i, f) in fps.iter().enumerate() {
        other_html.push_str(&fp_card(fp_base + i + 1, f));
    }
    // 速览表（其余区）
    let overview = overview_table(&other, &fps);

    // PoC 区
    let chain_html = chain_cards(d);

    // 每条被链接的发现都必须有卡（双向跳转契约）——含 FP 否决卡。
    let mut poc_html = String::new();
    for (i, f) in rce.iter().chain(other.iter()).chain(fps.iter()).enumerate() {
        poc_html.push_str(&poc_card(i + 1, f, d));
    }

    let summary = exec_summary(&rce, &other, &fps, d);
    // ordered = rce ++ other（partition 前的严重度降序全集，供关键发现精选）
    let mut ordered: Vec<&Finding> = rce.iter().chain(other.iter()).copied().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    let key_findings = key_findings(&ordered);
    let method = method_section(d);
    let hero = hero_section(d);

    let mut html = format!(
        r##"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>代码安全审计报告 — {project}</title>
<style>
{css}
</style>
</head>
<body>
<div class="layout">
<nav class="toc" id="toc">
  <div class="toc-brand"><span class="dot"></span><span class="t">AUDIT&nbsp;REPORT</span></div>
  <div class="toc-sec"><a href="#summary">执行摘要</a></div>
  <div class="toc-sec"><a href="#dashboard">风险总览仪表盘</a></div>
  <div class="toc-sec"><a href="#rce">一、RCE 风险链路分析</a></div>
  <ul class="toc-sub" id="toc-rce-list"></ul>
  <div class="toc-sec"><a href="#other">二、其余风险链路分析</a></div>
  <ul class="toc-sub" id="toc-other-list"></ul>
  <div class="toc-sec"><a href="#poc">三、风险复现与 PoC</a></div>
  <ul class="toc-sub" id="toc-poc-list"></ul>
  <div class="toc-sec"><a href="#method">四、方法说明与覆盖率</a></div>
  <div class="toc-filter">
    <span style="font-size:11px;color:var(--text-faint);width:100%;margin-bottom:2px;">按严重度筛选</span>
    <button class="active" data-filter="ALL">全部</button>
    <button data-filter="CRITICAL">CRITICAL</button>
    <button data-filter="HIGH">HIGH</button>
    <button data-filter="MEDIUM">MEDIUM</button>
    <button data-filter="LOW">LOW</button>
  </div>
</nav>
<div class="main">
{hero}
<section id="summary">
  <div class="section-head"><span class="idx">00</span><h2>执行摘要</h2></div>
  <p class="section-desc">{summary}</p>
</section>
<section id="dashboard">
  <div class="section-head"><span class="idx">01</span><h2>风险总览仪表盘</h2></div>
  <p class="section-desc">统计数字、分布条与环形图由脚本扫描全文 <code>.finding[data-sev]</code> 自动生成。</p>
  <div class="stat-grid" id="stat-grid"></div>
  <div class="sevbar" id="sevbar"></div>
  <div class="dash-flex">
    <div class="donut-wrap">
      <svg id="donut" width="128" height="128" viewBox="0 0 128 128"></svg>
      <div class="donut-legend" id="donut-legend"></div>
    </div>
    <div class="key-findings">
      <div class="lbl" style="font-family:var(--mono);font-size:10.5px;color:var(--text-faint);margin-bottom:6px;">关键发现（按严重度精选）</div>
      <ul>{key_findings}</ul>
    </div>
  </div>
</section>
<section id="rce">
  <div class="section-head"><span class="idx">02</span><h2>一、RCE 风险链路分析（最高优先级）</h2></div>
  <p class="section-desc">只收录能独立构成代码执行、或作为 RCE 链关键一跳的发现。每条附入口→中间跳转→汇点流程图；「复现与 PoC ↓」直达复现章节并高亮。</p>
  {rce_html}
  {chain_html}
</section>
<section id="other">
  <div class="section-head"><span class="idx">03</span><h2>二、其余风险链路分析</h2></div>
  <p class="section-desc">按严重度分组。速览表每行可点击跳转详情卡；负向结论（已否决）以轻卡片收编，保持可审计。</p>
  {overview}
  {other_html}
</section>
<section id="poc">
  <div class="section-head"><span class="idx">04</span><h2>三、风险复现与 PoC</h2></div>
  <p class="section-desc">每个 PoC 卡对应一条链路卡（id 后缀一致），「↑ 返回链路分析」跳回原始发现并高亮；代码块可一键复制。</p>
  <div class="toolbar">
    <button id="expand-all">全部展开</button>
    <button id="collapse-all">全部收起</button>
  </div>
  {poc_html}
</section>
{method}
</div>
</div>
<button class="back-top" id="back-top" aria-label="回到顶部">↑</button>
<script>
{js}
</script>
</body>
</html>
"##,
        project = esc(&d.project),
        css = TEMPLATE_CSS,
        js = TEMPLATE_JS,
        hero = hero,
        summary = summary,
        key_findings = key_findings,
        rce_html = rce_html,
        chain_html = chain_html,
        overview = overview,
        other_html = other_html,
        poc_html = poc_html,
        method = method,
    );
    // 离线承诺（REPORT-TEMPLATE.md）：零外部资源。报告含 mermaid 图时把渲染器
    // 内嵌到同一 script 块（UMD 先定义全局，template.js 再初始化）；无图报告
    // 不携带 3.3MB 库，保持轻量。
    if html.contains("class=\"mermaid\"") {
        html = html.replacen("<script>\n", &format!("<script>\n{MERMAID_JS};\n"), 1);
    }
    html
}

// ---------- sections ----------

fn hero_section(d: &ReportData) -> String {
    format!(
        r##"<header class="hero">
  <div class="eyebrow">CODE SECURITY AUDIT</div>
  <h1>{} 安全审计报告</h1>
  <p class="sub">{}</p>
  <div class="metarow">
    <span>仓库 / 版本 <b>{}</b></span>
    <span>审计时间 <b>{}</b></span>
    <span>审计方式 <b>{}</b></span>
    <span>报告生成 <b>{}</b></span>
  </div>
</header>"##,
        esc(&d.project),
        esc(&d.scope),
        esc(&d.repo_label),
        esc(&d.generated_at),
        esc(&d.method),
        esc(&d.agent_label),
    )
}

fn exec_summary(rce: &[&Finding], other: &[&Finding], fps: &[&Finding], d: &ReportData) -> String {
    let (mut crit, mut high) = (0, 0);
    for f in rce.iter().chain(other.iter()) {
        match f.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            _ => {}
        }
    }
    let rce_line = if rce.is_empty() {
        "本次未发现可直接构成 RCE 的链路。".to_string()
    } else {
        format!(
            "发现 {} 条 RCE 能力面，最危险的是「{}」{}。",
            rce.len(),
            esc(&short(&rce[0].title, 28)),
            rce[0]
                .preconditions
                .first()
                .map(|p| format!("（触发前置：{}）", esc(p)))
                .unwrap_or_default()
        )
    };
    let chain_line = d
        .chains
        .first()
        .map(|c| {
            format!(
                "存在可串联的攻击链：{}，影响：{}。",
                esc(&short(&c.title, 24)),
                esc(&short(&c.impact, 24))
            )
        })
        .unwrap_or_else(|| "未发现可串联的独立攻击链。".to_string());
    format!(
        "本次审计覆盖 {}，共判定 {} 条真漏洞（CRITICAL {} / HIGH {}）、否决 {} 条误报。{}{} 处置优先级：先堵 RCE 面与无鉴权入口，再按部署形态收敛暴露面（详见方法说明）。",
        esc(&d.scope),
        rce.len() + other.len(),
        crit,
        high,
        fps.len(),
        rce_line,
        chain_line
    )
}

fn key_findings(ordered: &[&Finding]) -> String {
    ordered
        .iter()
        .take(5)
        .map(|f| {
            format!(
                "<li>{}<div><a href=\"#finding-{}\" class=\"jump-ref\">{}</a><div style=\"color:var(--text-dim);font-size:12px;margin-top:2px;\">{}</div></div></li>",
                sev_chip(f),
                esc(&f.id),
                esc(&f.title),
                esc(&short(f.impact.as_deref().unwrap_or(&f.description), 60)),
            )
        })
        .collect()
}

fn finding_card(n: usize, f: &Finding, ev_map: &HashMap<String, &Evidence>, track: &str) -> String {
    let v = f.verdict.as_ref();
    let (verdict_label, verdict_cls) = match v.map(|v| v.conclusion) {
        Some(VerdictConclusion::TruePositive) => ("TRUE-POSITIVE", "ok"),
        Some(VerdictConclusion::Uncertain) => ("UNCERTAIN", "ghost"),
        _ => ("UNJUDGED", "ghost"),
    };

    // 问题 / 影响 双栏
    let problem = bullet_block("问题", &f.description, "");
    let impact = bullet_block("影响", f.impact.as_deref().unwrap_or(""), "impact");

    // mermaid 流程图（入口→跳→汇点）
    let mermaid = mermaid_flow(f, ev_map);
    let flow = if mermaid.is_empty() {
        String::new()
    } else {
        mermaid_block(&mermaid)
    };

    // 证据表（含触发条件 = preconditions，A1 两轴定级的可达性轴）
    let ev = evidence_table(f, ev_map);

    // 判定条
    let verdict_text = v.map(|v| esc(&v.reasoning)).unwrap_or_default();
    let verdict =
        format!("<div class=\"verdict\"><b>判定：{verdict_label}</b>&nbsp;— {verdict_text}</div>");

    let body = format!(
        "    <div class=\"f-grid\">{problem}{impact}</div>\n    {flow}\n    {ev}\n    {verdict}\n    \
         <div class=\"jump-row\"><a class=\"jump-link jump-ref\" href=\"#poc-{fid}\">复现与 PoC ↓</a></div>",
        fid = esc(&f.id),
    );
    let verdict_chip = format!("<span class=\"chip {verdict_cls}\">{verdict_label}</span>");
    card_shell(n, f, track, card_open(f), &verdict_chip, &body)
}

fn fp_card(n: usize, f: &Finding) -> String {
    let v = f.verdict.as_ref().unwrap();
    let body = format!(
        "    <div class=\"f-block full\"><div class=\"lbl\">结论</div><ul><li>{}</li></ul></div>\n    \
         <div class=\"verdict fp\"><b>判定：FALSE-POSITIVE</b>&nbsp;— {}</div>",
        esc(&v.reasoning),
        esc(&v.rebuttals.notes),
    );
    card_shell(
        n,
        f,
        "other",
        "",
        "<span class=\"chip ghost\">FALSE-POSITIVE</span>",
        &body,
    )
}

fn overview_table(other: &[&Finding], fps: &[&Finding]) -> String {
    let mut rows = String::new();
    let mut n = 0usize;
    for f in other.iter().chain(fps.iter()) {
        n += 1;
        let (label, cls) = if is_fp(f) {
            ("FALSE-POSITIVE", "ghost")
        } else {
            ("TRUE-POSITIVE", "ok")
        };
        rows.push_str(&format!(
            "<tr><td class=\"mono\">#{n}</td><td><a class=\"row-link\" href=\"#finding-{fid}\">{title}</a></td>\
             <td>{sev_chip}</td><td class=\"mono\">{loc}</td>\
             <td><span class=\"chip {cls}\">{label}</span></td>\
             <td><a class=\"jump-ref mono\" href=\"#poc-{fid}\" style=\"font-size:11px;\">PoC →</a></td></tr>",
            fid = esc(&f.id),
            title = esc(&short(&f.title, 42)),
            sev_chip = sev_chip(f),
            loc = loc(f),
        ));
    }
    table(
        "overview-table",
        &["编号", "标题", "严重度", "入口点", "判定", ""],
        &rows,
    )
}

fn poc_card(n: usize, f: &Finding, d: &ReportData) -> String {
    // 前置条件（A1）+ 复现包前置
    let mut pre: Vec<String> = f.preconditions.clone();
    if let Some(r) = &f.repro_pack {
        pre.extend(r.preconditions.iter().cloned());
    }
    if pre.is_empty() {
        pre.push("（未标注——按默认部署评估）".to_string());
    }
    let pre_html = li_list(pre.iter().map(String::as_str));

    let (steps, expect, actual) = match &f.repro_pack {
        Some(r) => (
            code_step("复现步骤", &r.request),
            esc(&r.expected),
            esc(&r.actual),
        ),
        None => (
            "<div class=\"poc-step\"><div class=\"lbl\">复现步骤</div><div class=\"codeblock\"><pre>（PoC 缺失——无法复现，需补充）</pre></div></div>".to_string(),
            String::new(),
            String::new(),
        ),
    };

    // 诚实三级 + 静态差分 + FP 否决，各有明确语义（不再 verdict·method 双写）
    let ver_chip = match &f.verification {
        Some(v) if v.verdict == "confirmed" => {
            chip_with_stamp("ok", "已实测验证 · live-prove", &v.at)
        }
        Some(v) if v.method == "fix-check" => chip_with_stamp(
            "ghost",
            &format!("修复校验 · 静态差分（post: {}）", esc(&v.post_state)),
            &v.at,
        ),
        Some(v) if v.verdict == "trigger-prove" => {
            chip_with_stamp("ok", "已触发验证 · trigger-prove", &v.at)
        }
        Some(v) => chip_with_stamp("ghost", "代码级证明 · code-proof", &v.at),
        None if f.verdict.as_ref().map(|v| v.conclusion)
            == Some(fiora_core::types::VerdictConclusion::FalsePositive) =>
        {
            "<span class=\"chip ghost\">误报否决 · 无需验证</span>".to_string()
        }
        None => "<span class=\"chip ghost\">未验证</span>".to_string(),
    };

    // 代码上下文（模板外加分项，放进步骤区）
    let ctx = d
        .snippets
        .get(&f.id)
        .map(|s| code_step("代码上下文", s))
        .unwrap_or_default();

    format!(
        r##"<div class="poc-card" id="poc-{fid}">
  <div class="poc-head">
    <div class="ttl">#{n} — {title}<span class="mono">对应链路：finding-{fid}</span></div>
    <a class="jump-link jump-ref" href="#finding-{fid}">↑ 返回链路分析</a>
  </div>
  <div class="poc-step"><div class="lbl">前置条件</div><ul>{pre_html}</ul></div>
  {steps}
  {ctx}
  <div class="expect-actual">
    <div class="box expect"><div class="lbl">预期（安全行为）</div>{expect}</div>
    <div class="box actual"><div class="lbl">实际</div>{actual}</div>
  </div>
  <div style="margin-top:10px;">{ver_chip}</div>
</div>"##,
        fid = esc(&f.id),
        title = esc(&f.title),
    )
}

/// C2 部署形态 × 风险面矩阵：按前置条件关键词聚合（泛化——不写死具体产品）
fn deployment_matrix(findings: &[Finding]) -> String {
    // 关键词 → 处置建议是数据表，不是分支：新增一类部署形态只加一行。
    #[rustfmt::skip]
    let buckets: [(&str, &[&str], &str); 5] = [
        ("默认部署", &["默认"], "部署即暴露，修复优先级最高"),
        ("需特定模式", &["模式", "rust-server", "mini-lb", "需启动"], "开启对应模式后按默认可打处置"),
        ("需组件服务", &["multimodal-gen", "post-training", "组件", "服务运行"], "部署该组件才进入攻击面"),
        ("需本地/侧车立足点", &["回环", "本地", "立足点", "侧车", "pod"], "提权/容器逃逸原语，K8s 共享网络需警惕"),
        ("供应链/工具语境", &["供应链", "benchmark", "数据集"], "数据/工具链投毒场景"),
    ];
    let mut rows = String::new();
    for (label, keys, advice) in buckets {
        let n = findings
            .iter()
            .filter(|f| {
                let pre = f.preconditions.join(" ").to_ascii_lowercase();
                keys.iter().any(|k| pre.contains(k))
            })
            .count();
        if n == 0 {
            continue;
        }
        rows.push_str(&format!(
            "<tr><td>{label}</td><td class=\"mono\">{n} 条</td><td>{advice}</td></tr>"
        ));
    }
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<div class=\"f-block full\"><div class=\"lbl\">部署形态 × 风险面</div>{}</div>",
        table("ev-table", &["部署形态", "命中", "处置建议"], &rows)
    )
}

fn method_section(d: &ReportData) -> String {
    let notes = li_list(d.method_notes.iter().map(String::as_str));
    let cov = &d.coverage;
    format!(
        r##"<section id="method">
  <div class="section-head"><span class="idx">05</span><h2>四、方法说明与覆盖率</h2></div>
  <div class="f-grid">
    <div class="f-block">
      <div class="lbl">审计方法</div>
      <ul><li>{method}</li>{notes}</ul>
    </div>
    {matrix}
    <div class="f-block">
      <div class="lbl">覆盖范围</div>
      <ul>
        <li>文件 {ft} 个（已审 {fa} / 跳过 {fs} / 未审 {fp}）</li>
        <li>候选 {ct} 条（规则 {cr} / 语义 {cs}）· 入口面 {se} 个</li>
        <li>未覆盖/受限说明：依赖 GPU 运行栈的验证项以代码级证明标注；生产风险需结合部署配置评估。</li>
      </ul>
    </div>
  </div>
  <p class="footnote">本报告由 {agent} 于 {date} 生成，判定基于静态代码追踪；动态验证结论由工作台 Agent 回填（<code>fiora verify record</code>），未回填的发现如实标注「未验证」。生产环境实际风险需结合部署配置综合评估。</p>
</section>"##,
        method = esc(&d.method),
        notes = notes,
        ft = cov.files_tracked,
        fa = cov.files_analyzed,
        fs = cov.files_skipped,
        fp = cov.files_pending,
        ct = cov.candidates_rule + cov.candidates_semantic,
        cr = cov.candidates_rule,
        cs = cov.candidates_semantic,
        se = cov.surface_entries,
        agent = esc(&d.agent_label),
        date = esc(&d.generated_at),
        matrix = deployment_matrix(&d.findings),
    )
}

// ---------- mermaid 流程图（入口→跳→汇点） ----------

fn mermaid_flow(f: &Finding, ev_map: &HashMap<String, &Evidence>) -> String {
    let mut steps: Vec<(String, &'static str)> = Vec::new();
    if let Some(ev) = f.evidence_ref.as_ref().and_then(|id| ev_map.get(id)) {
        for ent in &ev.entries {
            steps.push((
                format!("{}\n{}:{}", ent.symbol, ent.file, ent.line),
                "entry",
            ));
        }
        for hop in &ev.call_chain {
            steps.push((format!("{} → {}", hop.from, hop.to), "hop"));
        }
        steps.push((
            format!("{}\n{}:{}", ev.sink.symbol, ev.sink.file, ev.sink.line),
            "sink",
        ));
    } else if let Some(df) = &f.data_flow {
        for (i, seg) in df.split("->").enumerate() {
            let cls = if i == 0 { "entry" } else { "hop" };
            steps.push((seg.trim().to_string(), cls));
        }
        if let Some(last) = steps.last_mut() {
            last.1 = "sink";
        }
    }
    if steps.len() < 2 {
        return String::new();
    }
    // 去重相邻同名节点
    let mut nodes: Vec<(String, &'static str)> = Vec::new();
    for st in steps {
        if nodes.last().map(|(l, _)| l.as_str()) != Some(st.0.as_str()) {
            nodes.push(st);
        }
    }
    let mut m = String::from("flowchart LR\n");
    let ids: Vec<String> = (0..nodes.len()).map(|i| format!("N{i}")).collect();
    for (i, id) in ids.iter().enumerate() {
        m.push_str(&mermaid_node(id, &nodes[i].0));
    }
    for pair in ids.windows(2) {
        m.push_str(&mermaid_edge(&pair[0], &pair[1]));
    }
    for (i, (_, cls)) in nodes.iter().enumerate() {
        m.push_str(&format!("  class N{i} {cls};\n"));
    }
    m.push_str(
        "  classDef entry fill:#10202a,stroke:#5b9cf0,color:#eef1f6,stroke-width:1.2px;\n  \
         classDef hop fill:#1b222d,stroke:#2a3243,color:#c3cbda,stroke-width:1px;\n  \
         classDef sink fill:#2a1518,stroke:#ef5b5b,color:#eef1f6,stroke-width:1.4px;",
    );
    m
}

// ---------- helpers ----------

/// 一个轨道内的卡片，编号接着 `offset` 往下走——报告里的 #N 必须全局连续。
fn track_cards(
    findings: &[&Finding],
    offset: usize,
    ev_map: &HashMap<String, &Evidence>,
    track: &str,
) -> String {
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| finding_card(offset + i + 1, f, ev_map, track))
        .collect()
}

/// 发现卡片外壳：真阳性卡与误报否决卡只有判定徽章和卡体不同，头部是一份契约。
fn card_shell(
    n: usize,
    f: &Finding,
    track: &str,
    open: &str,
    verdict_chip: &str,
    body: &str,
) -> String {
    format!(
        r##"<details class="finding" id="finding-{fid}" data-sev="{sev}" data-track="{track}"{open}>
  <summary class="f-head">
    <span class="num">#{n}</span>
    <span class="f-title">{title}<span class="f-loc">{loc}</span></span>
    {sev_chip}
    {verdict_chip}
    <span class="caret">▸</span>
  </summary>
  <div class="f-body">
{body}
  </div>
</details>"##,
        fid = esc(&f.id),
        sev = sev_marks(f.severity).1,
        title = esc(&f.title),
        loc = loc(f),
        sev_chip = sev_chip(f),
    )
}

/// 高危卡默认展开（报告首屏要能直接读到高危链路）。
fn card_open(f: &Finding) -> &'static str {
    if f.severity.rank() >= 4 {
        " open"
    } else {
        ""
    }
}

/// 表格外壳：头部行只在这里写一次，`class` 随区块变。
fn table(cls: &str, headers: &[&str], rows: &str) -> String {
    let th: String = headers.iter().map(|h| format!("<th>{h}</th>")).collect();
    format!("<table class=\"{cls}\"><tr>{th}</tr>{rows}</table>")
}

/// mermaid 图外壳：流程图与攻击链卡共用同一个容器。
fn mermaid_block(mermaid: &str) -> String {
    format!("<div class=\"flowchart\"><div class=\"mermaid\">\n{mermaid}\n</div></div>")
}

/// mermaid 节点声明：标签里的双引号会打断语法，先换单引号再转义（两处共用）。
fn mermaid_node(id: &str, label: &str) -> String {
    format!("  {id}[\"{}\"]\n", esc(&label.replace('"', "'")))
}

fn mermaid_edge(from: &str, to: &str) -> String {
    format!("  {from} --> {to}\n")
}

/// `file:line`（已转义）。卡片与速览表都要写一次，只有这里拼。
fn loc(f: &Finding) -> String {
    esc(&format!("{}:{}", f.file, f.line))
}

fn li(text: &str) -> String {
    format!("<li>{}</li>", esc(text))
}

fn li_list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    items.into_iter().map(li).collect()
}

/// 严重度徽章。`sev_class` 与 `sev_label` 永远成对出现，配错了只是静默的样式错位。
fn sev_chip(f: &Finding) -> String {
    let (cls, label) = sev_marks(f.severity);
    format!("<span class=\"chip {cls}\">{label}</span>")
}

/// 验证徽章 + 时间戳：四类诚实等级共用同一个外壳，只有措辞与配色不同。
fn chip_with_stamp(cls: &str, label: &str, at: &str) -> String {
    format!(
        "<span class=\"chip {cls}\">{label}</span>&nbsp;<span class=\"chip ghost\">{}</span>",
        esc(at)
    )
}

/// 「标签 + 可复制代码块」步骤：复现请求与代码上下文是同一个外壳。
fn code_step(label: &str, body: &str) -> String {
    format!(
        "<div class=\"poc-step\"><div class=\"lbl\">{label}</div>\
         <div class=\"codeblock\"><button class=\"copy-btn\">复制</button><pre>{}</pre></div></div>",
        esc(body)
    )
}

fn bullet_block(label: &str, text: &str, cls: &str) -> String {
    let items = li_list(text.split('\n').map(str::trim).filter(|l| !l.is_empty()));
    format!("<div class=\"f-block {cls}\"><div class=\"lbl\">{label}</div><ul>{items}</ul></div>")
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// 严重度的 (CSS class, 显示标签)。同源同表——分成两个 match 迟早漏改一处。
fn sev_marks(s: Severity) -> (&'static str, &'static str) {
    match s {
        Severity::Critical => ("crit", "CRITICAL"),
        Severity::High => ("high", "HIGH"),
        Severity::Medium => ("med", "MEDIUM"),
        Severity::Low => ("low", "LOW"),
        Severity::Info => ("low", "INFO"),
        Severity::HighBug => ("low", "HIGH_BUG"),
        Severity::Bug => ("low", "BUG"),
    }
}

// 证据表（含 A1 触发条件 / 证据等级 / 汇点）
fn evidence_table(f: &Finding, ev_map: &HashMap<String, &Evidence>) -> String {
    let ev = f.evidence_ref.as_ref().and_then(|id| ev_map.get(id));
    let sink = ev
        .map(|e| format!("{} — {}:{}", e.sink.symbol, e.sink.file, e.sink.line))
        .unwrap_or_else(|| format!("{}:{}", f.file, f.line));
    let entry = ev
        .and_then(|e| e.entries.first())
        .map(|en| format!("{} — {}:{}", en.symbol, en.file, en.line))
        .unwrap_or_else(|| "（未追踪到入口）".to_string());
    let grade = ev
        .map(|e| format!("{:?}", e.grade))
        .unwrap_or_else(|| "-".to_string());
    let pre = if f.preconditions.is_empty() {
        "（未标注）".to_string()
    } else {
        f.preconditions.join("；")
    };
    let conf = f
        .verdict
        .as_ref()
        .map(|v| format!("{:?}", v.confidence))
        .unwrap_or_default();
    format!(
        "<table class=\"ev-table\"><tr><th>字段</th><th>内容</th></tr>\
         <tr><td>入口点</td><td class=\"mono\">{}</td></tr>\
         <tr><td>汇点</td><td class=\"mono\">{}</td></tr>\
         <tr><td>触发条件</td><td>{}</td></tr>\
         <tr><td>证据等级</td><td>{}</td></tr>\
         <tr><td>置信度</td><td>{}</td></tr></table>",
        esc(&entry),
        esc(&sink),
        esc(&pre),
        esc(&grade),
        esc(&conf),
    )
}
