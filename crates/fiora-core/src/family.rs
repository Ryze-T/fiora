//! 能力族视图：把离散发现按"攻击能力"聚合，并按前置条件排可达性座次。
//!
//! 实战动机：审计后被问"还有哪些 RCE / 哪些无条件"时，人工翻账本排座次
//! 既慢又易错。这里把两件事机械化：
//!
//! 1. **族分类**（classify）：category/slug/title/sink/impact 关键词 → 能力族
//!    （RCE / SSRF / 任意文件写 / 反序列化 / 注入 / 鉴权 / …）；
//! 2. **可达性档位**（reach_tier）：preconditions 文本 → 档位 + 条件数，
//!    座次 = 档位升序、条件数升序（越无条件越靠前）。

use crate::types::Finding;

/// 攻击能力族。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// 代码/命令执行（含注入、反序列化执行、文件写→执行链）。
    Rce,
    /// 服务端请求伪造 / 任意目标请求。
    Ssrf,
    /// 任意文件写（含路径穿越、对象键穿越）。
    Awf,
    /// 反序列化/加载面（未确认执行的）。
    Deser,
    /// 注入族（SQL/命令/模板/日志，未确认执行的）。
    Injection,
    /// 鉴权/授权缺失、越权、伪造。
    Authz,
    /// 任意文件读 / 信息泄露。
    InfoLeak,
    /// 拒绝服务 / 资源失控。
    Dos,
    /// 供应链 / 依赖 / CI 面。
    SupplyChain,
    /// 其他。
    Other,
}

impl Family {
    pub fn label(&self) -> &'static str {
        match self {
            Family::Rce => "RCE",
            Family::Ssrf => "SSRF",
            Family::Awf => "AWF(任意文件写)",
            Family::Deser => "反序列化/加载",
            Family::Injection => "注入",
            Family::Authz => "鉴权/授权",
            Family::InfoLeak => "信息泄露/任意读",
            Family::Dos => "DoS/资源失控",
            Family::SupplyChain => "供应链/CI",
            Family::Other => "其他",
        }
    }
}

/// 可达性档位（值越小越易达）。座次 = 档位升序。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReachTier {
    /// 无条件：默认部署、无需凭据（"默认可打/任何人"）。
    Unconditional = 0,
    /// 网络可达即打（同网络/端口可达）。
    NetworkReach = 1,
    /// 需部署形态/功能开关（模式、flag、组件开启）。
    DeployMode = 2,
    /// 供应链语境（数据集/模型/依赖投毒、第三方资源）。
    SupplyChain = 3,
    /// 工作流触发（操作者/agent/评审流程按默认走）。
    Workflow = 4,
}

impl ReachTier {
    pub fn label(&self) -> &'static str {
        match self {
            ReachTier::Unconditional => "无条件",
            ReachTier::NetworkReach => "网络可达",
            ReachTier::DeployMode => "部署形态",
            ReachTier::SupplyChain => "供应链",
            ReachTier::Workflow => "工作流",
        }
    }
}

const TIER_UNCONDITIONAL: &[&str] = &[
    "默认可打",
    "无条件",
    "任何人",
    "无需凭据",
    "无需任何凭据",
    "未配置 key 时",
];
const TIER_NETWORK: &[&str] = &[
    "可达",
    "网络",
    "端口",
    "监听",
    "同网络",
    "同集群",
    "同 VPC",
    "内网",
];
const TIER_DEPLOY: &[&str] = &["需", "模式", "开启", "启动", "部署", "flag", "--", "配置"];
const TIER_SUPPLY: &[&str] = &[
    "供应链",
    "数据集",
    "投毒",
    "第三方",
    "模型仓库",
    "依赖",
    "PR",
    "fork",
];
const TIER_WORKFLOW: &[&str] = &[
    "操作者",
    "agent",
    "评审",
    "流程",
    "技能",
    "执行 proof",
    "summarize",
    "评测脚本",
];

/// 严重度阈值（单一真值）：`all`/`info`=1 … `critical`=5。
/// 未知取值返回 None，调用方决定是报错还是回退。
pub fn severity_threshold(level: &str) -> Option<u8> {
    match level.to_ascii_lowercase().as_str() {
        "all" | "info" => Some(1),
        "low" => Some(2),
        "medium" => Some(3),
        "high" => Some(4),
        "critical" => Some(5),
        _ => None,
    }
}

/// 输出过滤 / CI 门禁共用口径：默认只看高危及以上（rank>=4），`all` 显式放开。
/// 低危仍落账（覆盖率不变），只是不进默认视图。
pub fn passes_severity(f: &Finding, severity: &str) -> bool {
    let floor = severity_threshold(severity).unwrap_or(4);
    f.severity.rank() >= floor
}

/// CWE 标准映射（披露标准化）：category/slug/关键词 → CWE-ID。
/// 优先 category/slug 精确表，其次危害关键词兑底。
/// 仅按 category/slug 命中的 CWE——确定性、可辩护（导出 SARIF/机器消费用这个，
/// 不拿描述里的关键词去猜一个 CWE 出来）。
pub fn cwe_from_category(f: &Finding) -> Option<&'static str> {
    let cat = f.category.to_lowercase();
    let slug = f.slug.to_lowercase();
    // 先精确等值，再按 key 长度从长到短做包含匹配——否则 "nosqli" 会被
    // 更早出现的 "sqli" 抢走（CWE-89 而不是 CWE-943）。
    for (key, cwe) in CWE_EXACT {
        if cat == *key || slug == *key {
            return Some(cwe);
        }
    }
    if let Some((_, cwe)) = CWE_TABLE
        .iter()
        .find(|(key, _)| cat == *key || slug == *key)
    {
        return Some(cwe);
    }
    let mut keys: Vec<&(&str, &str)> = CWE_TABLE.iter().collect();
    keys.sort_by_key(|(key, _)| std::cmp::Reverse(key.len()));
    keys.iter()
        .find(|(key, _)| cat.contains(key) || slug.contains(key))
        .map(|(_, cwe)| *cwe)
}

/// 展示用 CWE：先查表，再退回描述关键词。关键词命中是**启发式**，
/// 报告可以用它做人读提示，机器消费方请用 [`cwe_from_category`]。
pub fn cwe_for(f: &Finding) -> Option<&'static str> {
    if let Some(cwe) = cwe_from_category(f) {
        return Some(cwe);
    }
    let hay = format!(
        "{} {} {}",
        f.title,
        f.impact.clone().unwrap_or_default(),
        f.description
    )
    .to_lowercase();
    for (key, cwe) in CWE_KEYWORDS {
        if hay.contains(&key.to_lowercase()) {
            return Some(cwe);
        }
    }
    None
}

const CWE_TABLE: &[(&str, &str)] = &[
    ("sqli", "CWE-89"),
    ("cmdi", "CWE-78"),
    ("code-injection", "CWE-95"),
    ("rce-python-eval", "CWE-95"),
    ("xss", "CWE-79"),
    ("ssrf", "CWE-918"),
    ("path-traversal", "CWE-22"),
    ("lfi", "CWE-22"),
    ("deser", "CWE-502"),
    ("unsafe-deserialization", "CWE-502"),
    ("auth-bypass", "CWE-287"),
    ("missing-auth", "CWE-306"),
    ("authz", "CWE-862"),
    ("idor", "CWE-639"),
    ("hardcoded-secret", "CWE-798"),
    ("hardcoded-secrets", "CWE-798"),
    ("sensitive-data", "CWE-200"),
    ("nosqli", "CWE-943"),
    ("session", "CWE-613"),
    ("weak-crypto", "CWE-327"),
    ("open-redirect", "CWE-601"),
    ("race", "CWE-362"),
    ("xxe", "CWE-611"),
    ("ssti", "CWE-1336"),
    ("csrf", "CWE-352"),
    ("upload", "CWE-434"),
    ("log-injection", "CWE-117"),
    ("prototype-pollution", "CWE-1321"),
    ("dos", "CWE-400"),
    ("supply-chain", "CWE-829"),
];

/// 只允许**精确等值**的短键：`rce`/`auth` 这类做子串匹配会误伤
/// （"brute-force" 含 "rce"，"authorization" 含 "auth"）。
const CWE_EXACT: &[(&str, &str)] = &[("rce", "CWE-94"), ("auth", "CWE-287")];

const CWE_KEYWORDS: &[(&str, &str)] = &[
    ("sql 注入", "CWE-89"),
    ("sql注入", "CWE-89"),
    ("命令注入", "CWE-78"),
    ("命令执行", "CWE-78"),
    ("任意文件写", "CWE-73"),
    ("路径穿越", "CWE-22"),
    ("反序列化", "CWE-502"),
    ("模板注入", "CWE-1336"),
    ("ssrf", "CWE-918"),
    ("服务端请求", "CWE-918"),
    ("越权", "CWE-862"),
    ("未授权", "CWE-306"),
    ("硬编码", "CWE-798"),
    ("xxe", "CWE-611"),
    ("代码执行", "CWE-94"),
    ("任意代码", "CWE-94"),
];

/// 由 preconditions 文本推可达性档位：取所有条件中最靠后（最难）的档位。
/// 空条件列表 = Unconditional（账本契约里 preconditions 必填，空即无前置）。
pub fn reach_tier(preconditions: &[String]) -> ReachTier {
    if preconditions.is_empty() {
        return ReachTier::Unconditional;
    }
    let mut tier = ReachTier::Unconditional;
    for p in preconditions {
        let t = classify_condition(p);
        if t as u8 > tier as u8 {
            tier = t;
        }
    }
    tier
}

fn classify_condition(text: &str) -> ReachTier {
    // 显式"默认可打/任何人"优先判定（一句话定档）。
    if TIER_UNCONDITIONAL.iter().any(|k| text.contains(k)) {
        return ReachTier::Unconditional;
    }
    if TIER_WORKFLOW.iter().any(|k| text.contains(k)) {
        return ReachTier::Workflow;
    }
    if TIER_SUPPLY.iter().any(|k| text.contains(k)) {
        return ReachTier::SupplyChain;
    }
    if TIER_NETWORK.iter().any(|k| text.contains(k)) {
        return ReachTier::NetworkReach;
    }
    if TIER_DEPLOY.iter().any(|k| text.contains(k)) {
        return ReachTier::DeployMode;
    }
    // 未识别条件保守视为部署形态门槛（比"网络可达"更难）。
    ReachTier::DeployMode
}

/// 族分类：能力词（强危害声称）优先于 category 词表，再关键词兜底。
/// 实战例：category=deser 但 impact 写“可实现代码执行”的发现，在
/// “还有哪些 RCE”的座次表里必须入 RCE 族。
pub fn classify(f: &Finding) -> Family {
    let hay = format!(
        "{} {} {} {} {}",
        f.title,
        f.impact.clone().unwrap_or_default(),
        f.description,
        f.sink_symbol,
        f.probe_shape.clone().unwrap_or_default()
    )
    .to_lowercase();
    // 1) RCE 专道：只认执行面事实（类别/原语 sink/title 声称）——
    //    impact 的升级推测不算（实战教训："可能导致代码执行"把越权/SSRF 拖进 RCE 族）。
    let cat = f.category.to_lowercase();
    let slug = f.slug.to_lowercase();
    let rce_cats = [
        "rce",
        "code-injection",
        "insecure-deserialization",
        "cmdi",
        "rce-python-eval",
    ];
    let exec_prims = [
        "eval(",
        "exec(",
        "system(",
        "pickle.load",
        "unserialize",
        "deserialize",
        "run_script",
        "render_template_string",
    ];
    let title_rce = [
        "rce",
        "代码执行",
        "命令执行",
        "任意代码",
        "执行任意",
        "getshell",
    ];
    if rce_cats.contains(&cat.as_str())
        || rce_cats.contains(&slug.as_str())
        || exec_prims
            .iter()
            .any(|k| f.sink_symbol.to_lowercase().contains(k))
        || title_rce
            .iter()
            .any(|k| crate::util::contains_word(&f.title, k))
    {
        return Family::Rce;
    }
    // 2) 强能力词（其余族）
    for (key, fam) in STRONG_KEYWORDS {
        if hay.contains(&key.to_lowercase()) {
            return *fam;
        }
    }
    // 3) category/slug 精确词表
    for (key, fam) in CATEGORY_TABLE {
        if cat == *key || slug == *key {
            return *fam;
        }
    }
    // 4) 弱关键词兜底
    for (key, fam) in WEAK_KEYWORDS {
        if hay.contains(&key.to_lowercase()) {
            return *fam;
        }
    }
    Family::Other
}

const CATEGORY_TABLE: &[(&str, Family)] = &[
    ("rce", Family::Rce),
    ("rce-python-eval", Family::Rce),
    ("cmdi", Family::Rce),
    ("code-exec", Family::Rce),
    ("ssrf", Family::Ssrf),
    ("deser", Family::Deser),
    ("unsafe-deserialization", Family::Deser),
    ("sqli", Family::Injection),
    ("injection", Family::Injection),
    ("xss", Family::Injection),
    ("authz", Family::Authz),
    ("auth-bypass", Family::Authz),
    ("idor", Family::Authz),
    ("lfi", Family::InfoLeak),
    ("info-leak", Family::InfoLeak),
    ("dos", Family::Dos),
    ("supply-chain", Family::SupplyChain),
];

/// 强能力词（危害声称直接定族——执行族先于泄露族，"文件写→RCE"入 RCE 族）。
const STRONG_KEYWORDS: &[(&str, Family)] = &[
    ("任意文件写", Family::Awf),
    ("文件写入", Family::Awf),
    ("路径穿越", Family::Awf),
    ("对象键穿越", Family::Awf),
    ("ssrf", Family::Ssrf),
    ("服务端请求", Family::Ssrf),
];

/// 弱关键词（类别语义，强词未命中时的兑底）。
const WEAK_KEYWORDS: &[(&str, Family)] = &[
    ("pickle", Family::Deser),
    ("反序列化", Family::Deser),
    ("deserialize", Family::Deser),
    ("unmarshal", Family::Deser),
    ("注入", Family::Injection),
    ("鉴权", Family::Authz),
    ("越权", Family::Authz),
    ("伪造", Family::Authz),
    ("未授权", Family::Authz),
    ("信息泄露", Family::InfoLeak),
    ("任意读", Family::InfoLeak),
    ("拒绝服务", Family::Dos),
    ("供应链", Family::SupplyChain),
];

/// 座次行：族视图的排序单元。
pub struct FamilyRow {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub tier: ReachTier,
    pub precondition_count: usize,
}

/// 按族聚合 + 座次排序（档位升序、条件数升序、严重度降序兜底）。
pub fn rank_by_family(findings: &[&Finding]) -> Vec<(Family, Vec<FamilyRow>)> {
    let mut groups: Vec<(Family, Vec<FamilyRow>)> = Vec::new();
    for f in findings {
        let fam = classify(f);
        let row = FamilyRow {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: format!("{:?}", f.severity),
            tier: reach_tier(&f.preconditions),
            precondition_count: f.preconditions.len(),
        };
        match groups.iter_mut().find(|(g, _)| *g == fam) {
            Some((_, rows)) => rows.push(row),
            None => groups.push((fam, vec![row])),
        }
    }
    for (_, rows) in groups.iter_mut() {
        rows.sort_by(|a, b| {
            a.tier
                .cmp(&b.tier)
                .then(a.precondition_count.cmp(&b.precondition_count))
                .then(b.severity.cmp(&a.severity))
        });
    }
    groups.sort_by_key(|(fam, _)| *fam as u8);
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn f(title: &str, cat: &str, impact: Option<&str>, pre: Vec<&str>) -> Finding {
        Finding {
            id: format!("id-{title}"),
            slug: cat.into(),
            title: title.into(),
            severity: Severity::High,
            category: cat.into(),
            file: "a.py".into(),
            line: 1,
            end_line: None,
            sink_symbol: "s".into(),
            enclosing_fn: "g".into(),
            probe_shape: None,
            description: String::new(),
            impact: impact.map(|s| s.to_string()),
            preconditions: pre.into_iter().map(|s| s.to_string()).collect(),
            data_flow: None,
            evidence_ref: None,
            repro_pack: None,
            verdict: None,
            chain_ids: vec![],
            agent: None,
            verification: None,
        }
    }

    #[test]
    fn impact_speculation_does_not_make_rce() {
        // 实战教训：netbox 审计 7 条越权/SSRF 因 impact 含"代码执行"被拖进 RCE 章。
        let mut idor = f(
            "GraphQL GFK 预取未限权，可越权读 Interface",
            "authz",
            None,
            vec![],
        );
        idor.impact = Some("攻击者可能进而实现代码执行".into());
        idor.sink_symbol = "resolve_gfk".into();
        assert_ne!(classify(&idor), Family::Rce, "impact 升级推测不算 RCE");
        assert_eq!(classify(&idor), Family::Authz);
        // sink 是执行原语的才算
        let mut script = f("未授权脚本执行", "authz", None, vec![]);
        script.sink_symbol = "run_script".into();
        assert_eq!(classify(&script), Family::Rce, "执行原语 sink 入 RCE");
        // title 显式声称的也算
        let claimed = f("XX 处可执行任意命令", "other", None, vec![]);
        assert_eq!(classify(&claimed), Family::Rce);
    }

    #[test]
    fn classifies_rce_family() {
        assert_eq!(
            classify(&f(
                "权重加载可 RCE",
                "deser",
                Some("可实现代码执行"),
                vec![]
            )),
            Family::Rce
        );
        assert_eq!(classify(&f("任意文件写", "awf", None, vec![])), Family::Awf);
        assert_eq!(
            classify(&f("SSRF 漏洞", "ssrf", None, vec![])),
            Family::Ssrf
        );
        assert_eq!(
            classify(&f("未鉴权改权重", "authz", None, vec![])),
            Family::Authz
        );
    }

    #[test]
    fn tier_ordering() {
        assert_eq!(reach_tier(&[]), ReachTier::Unconditional);
        assert_eq!(
            reach_tier(&["默认可打：端口可达即可".into()]),
            ReachTier::Unconditional
        );
        assert_eq!(
            reach_tier(&["攻击者网络可达 dist_init 端口".into()]),
            ReachTier::NetworkReach
        );
        assert_eq!(
            reach_tier(&["需 PD 分离部署".into()]),
            ReachTier::DeployMode
        );
        assert_eq!(
            reach_tier(&["需数据集投毒（供应链）".into()]),
            ReachTier::SupplyChain
        );
        assert_eq!(
            reach_tier(&["评审者按默认流程执行 proof".into()]),
            ReachTier::Workflow
        );
        // 多条件取最难档位
        assert_eq!(
            reach_tier(&["端口可达".into(), "需多节点部署".into()]),
            ReachTier::DeployMode
        );
    }

    #[test]
    fn default_severity_shows_high_and_critical_only() {
        // 用户约定：默认只看高危及以上，--severity all 才放开。
        let mut hi = f("高危洞", "authz", None, vec![]);
        hi.severity = Severity::Critical;
        let mut mid = f("中危洞", "authz", None, vec![]);
        mid.severity = Severity::Medium;
        assert!(passes_severity(&hi, "high"));
        assert!(!passes_severity(&mid, "high"), "中低危默认不展示");
        assert!(passes_severity(&mid, "all"), "all 显式放开");
    }

    #[test]
    fn ranks_unconditional_first() {
        let a = f("无条件洞", "authz", None, vec!["默认可打"]);
        let b = f("形态洞", "authz", None, vec!["需 PD 分离部署", "端口可达"]);
        let c = f("网络洞", "authz", None, vec!["端口可达"]);
        let groups = rank_by_family(&[&b, &c, &a]);
        let (_, rows) = &groups[0];
        assert_eq!(rows[0].title, "无条件洞");
        assert_eq!(rows[1].title, "网络洞");
        assert_eq!(rows[2].title, "形态洞");
    }

    #[test]
    fn exact_category_wins_over_shorter_substring() {
        // "nosqli" 含 "sqli"：精确等值必须先命中，否则 NoSQL 被错标成 SQL 注入
        assert_eq!(
            cwe_from_category(&f("t", "nosqli", None, vec![])),
            Some("CWE-943")
        );
        assert_eq!(
            cwe_from_category(&f("t", "sqli", None, vec![])),
            Some("CWE-89")
        );
    }

    #[test]
    fn keyword_fallback_is_not_used_for_machine_mapping() {
        // 描述里提到「任意代码」不代表这条发现就是代码注入
        let mut f = f("t", "sensitive-data", None, vec![]);
        f.description = "明文存储；一旦泄露可导致任意代码执行".into();
        assert_eq!(cwe_from_category(&f), Some("CWE-200"));
        assert_ne!(cwe_for(&f), Some("CWE-94"), "精确类别优先，不被关键词抢");
    }
}
