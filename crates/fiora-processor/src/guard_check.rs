//! 语义核查表（semantic guard tables）——"安全语义在场 + 未论证绕过 → 定性降级"
//! 的机械模式，一族一张表。
//!
//! 覆盖五族：RCE（加载语义）/ SQLi（参数化）/ SSRF（目标围栏）/ 路径（路径围栏）/
//! 模板注入（沙箱/转义）。实战动机：判定层反复对**穿过安全机制的 sink** 夸大定性
//! （经 weights_only=True 的"RCE"、经参数化 API 的"SQL 注入"）——机械化纠偏。
//!
//! 两种降级策略（按族配置）：
//! - **安全语义在场降级**（全部族）：现场配了围栏/参数化/过滤器且未论证绕过 → 降级；
//! - **无据降级**（仅 RCE）：加载类 sink 的 RCE 定性不引用任何语义 → 降级。
//!   其余族不做无据降级（避免对普通发现误伤）。
//!
//! 自明危险原语（`known_unsafe_sinks`：裸 pickle.loads / Marshal.load 等）在
//! 无安全语义在场时直接保留原判——裸名即危险，不逼 judge 写废话。
//!
//! 附带：CVE 标记消歧（sink 语境含 `CVE-YYYY-NNNNN` = 已知洞，自动标注）。

use fiora_core::{Finding, Severity};

/// 一族定性核查配置。
pub struct GuardFamily {
    pub label: &'static str,
    /// 该族的定性声称关键词。
    pub claim_keywords: &'static [&'static str],
    /// sink 识别（低门槛——宁可多核查不漏）。
    pub sink_markers: &'static [&'static str],
    /// 已知安全语义：(匹配串, 语义说明)。
    pub safe_semantics: &'static [(&'static str, &'static str)],
    /// 危险语义论证短语（judge 显式论述 = 有据，尊重原判）。
    /// 注意：裸函数名不算论证——有据 = 指出危险特征（无过滤/裸解/绕过/危险 flag）。
    pub unsafe_citations: &'static [&'static str],
    /// 自明危险原语（裸 sink 名即危险；与安全语义冲突时安全语义优先）。
    pub known_unsafe_sinks: &'static [&'static str],
    /// 无安全语义且无论证时也降级（仅 RCE 开启）。
    pub ungrounded_downgrade: bool,
    /// 降级后的严重度封顶。
    pub cap: Severity,
}

/// RCE（加载/反序列化语义）。
pub const RCE: GuardFamily = GuardFamily {
    label: "RCE",
    claim_keywords: &[
        "RCE",
        "rce",
        "代码执行",
        "执行代码",
        "命令执行",
        "任意命令",
        "任意代码",
        "远程代码",
        "getshell",
        "获取 shell",
        "shell 执行",
    ],
    sink_markers: &[
        "load",
        "deserial",
        "pickle",
        "unpickle",
        "unmarshal",
        "from_bytes",
        "decode",
        "restore",
        "read_object",
        "loads",
        "readobject",
        "fromxml",
        "parseobject",
        "readresolve",
        "readunshared",
        "unserialize",
        "runinnewcontext",
        "marshal",
        "gob",
        "newdecoder",
    ],
    safe_semantics: &[
        // Python
        (
            "weights_only=True",
            "torch.load(weights_only=True) 禁 pickle 执行",
        ),
        (
            "SafeUnpickler",
            "精确白名单反序列化器（未见绕过引用时视为安全）",
        ),
        ("safe_load", "yaml.safe_load 安全解析"),
        (
            "find_class",
            "自定义 find_class 白名单（未见绕过引用时视为安全）",
        ),
        // Java
        ("ObjectInputFilter", "JEP 290 反序列化过滤器"),
        ("ValidatingObjectInputStream", "commons-io 白名单反序列化"),
        (
            "SafeConstructor",
            "snakeyaml SafeConstructor（禁任意类型实例化）",
        ),
        ("allowTypes", "XStream/Jackson 白名单配置"),
        ("autoTypeSupport=false", "Fastjson autoType 关闭"),
        ("safeMode", "Fastjson safeMode"),
        // Node / Go / 跨语言
        ("JSON.parse", "JSON.parse 纯数据（无执行语义）"),
        ("secure-load", "js-yaml v4 默认安全（禁自定义类型）"),
        ("json.Unmarshal", "encoding/json 纯数据（无执行语义）"),
        ("safetensors", "safetensors 安全格式（无 pickle 面）"),
        ("protobuf", "protobuf typed 解码（无 pickle 面）"),
        (
            "msgspec",
            "msgspec typed 解码（struct schema，非不透明反序列化）",
        ),
        ("serde_json", "serde typed 解码（无执行语义）"),
    ],
    unsafe_citations: &[
        "weights_only=False",
        "weights_only = False",
        "裸 pickle",
        "裸解",
        "裸反序列化",
        "无白名单",
        "未设白名单",
        "无过滤",
        "无 ObjectInputFilter",
        "无过滤器",
        "无 SafeConstructor",
        "白名单绕过",
        "绕过白名单",
        "加固绕过",
        "绕过",
        "bypass",
        "enableDefaultTyping",
        "autoType",
        "unsafe_load",
    ],
    known_unsafe_sinks: &[
        "pickle.loads",
        "pickle.load",
        "marshal.load",
        "readunshared",
        "xmldecoder",
        "node-serialize",
        "funcster",
        "yaml.load(",
        "dill.load",
    ],
    ungrounded_downgrade: true,
    cap: Severity::High,
};

/// SQL 注入（参数化语义）。
pub const SQLI: GuardFamily = GuardFamily {
    label: "SQLi",
    claim_keywords: &["SQL 注入", "sql注入", "sqli", "SQL injection", "注入数据库"],
    sink_markers: &["query", "execute", "exec", "raw", "sql", "prepare"],
    safe_semantics: &[
        ("= ?", "占位符参数化"),
        ("prepare", "prepared statement"),
        ("Prepare", "prepared statement"),
        ("setParameter", "JPA 参数绑定"),
        ("bind_param", "参数绑定"),
        ("Parameterized", "参数化 API"),
        ("JdbcTemplate", "参数化模板"),
        ("where(", "ORM 条件构造"),
        ("filter(", "ORM 条件构造"),
    ],
    unsafe_citations: &[
        "拼接",
        "fmt.Sprintf",
        "字符串格式化",
        "f-string",
        "concat",
        "format!",
        "无参数化",
        "绕过",
        "bypass",
    ],
    known_unsafe_sinks: &[],
    ungrounded_downgrade: false,
    cap: Severity::High,
};

/// SSRF（目标围栏语义）。
pub const SSRF: GuardFamily = GuardFamily {
    label: "SSRF",
    claim_keywords: &["SSRF", "服务端请求", "server-side request"],
    sink_markers: &[
        "request", "fetch", "download", "get(", "url", "http", "curl",
    ],
    safe_semantics: &[
        ("allowlist", "目标白名单"),
        ("白名单", "目标白名单"),
        ("is_safe_url", "URL 安全校验"),
        ("block_private", "内网地址拦截"),
        ("内网校验", "内网地址校验"),
        ("host 校验", "host 校验"),
        ("no_proxy 校验", "代理策略校验"),
    ],
    unsafe_citations: &[
        "无内网校验",
        "无 host 校验",
        "无白名单",
        "未校验",
        "校验绕过",
        "绕过",
        "bypass",
    ],
    known_unsafe_sinks: &[],
    ungrounded_downgrade: false,
    cap: Severity::High,
};

/// 路径（路径围栏语义）。
pub const PATH: GuardFamily = GuardFamily {
    label: "路径",
    claim_keywords: &[
        "路径穿越",
        "任意文件",
        "目录穿越",
        "path traversal",
        "任意写",
        "任意读",
    ],
    sink_markers: &["open(", "read", "write", "path", "file", "join(", "save"],
    safe_semantics: &[
        ("ensure_path_within", "路径围栏"),
        ("realpath", "路径归一 + 围栏"),
        ("is_relative_to", "包含性校验"),
        ("basename", "文件名基元化"),
        ("startswith(root", "前缀围栏"),
        ("normpath 校验", "归一化校验"),
    ],
    unsafe_citations: &[
        "未净化",
        "无围栏",
        "围栏未",
        "未传",
        "拼接",
        "穿越",
        "绕过",
        "bypass",
        "未校验",
    ],
    known_unsafe_sinks: &[],
    ungrounded_downgrade: false,
    cap: Severity::High,
};

/// 模板注入（沙箱/转义语义）。
pub const TEMPLATE: GuardFamily = GuardFamily {
    label: "模板注入",
    claim_keywords: &["模板注入", "SSTI", "template injection"],
    sink_markers: &[
        "render",
        "template",
        "compile",
        "jinja",
        "ejs",
        "pug",
        "freemarker",
    ],
    safe_semantics: &[
        ("autoescape", "autoescape 开启"),
        ("SandboxedEnvironment", "沙箱模板环境"),
        ("sandbox", "沙箱执行"),
        ("html.escape", "输出转义"),
        ("escape(", "输出转义"),
    ],
    unsafe_citations: &[
        "render_template_string",
        "用户输入拼模板",
        "未转义",
        "autoescape=False",
        "绕过",
        "bypass",
    ],
    known_unsafe_sinks: &[],
    ungrounded_downgrade: false,
    cap: Severity::High,
};

pub const ALL_FAMILIES: &[&GuardFamily] = &[&RCE, &SQLI, &SSRF, &PATH, &TEMPLATE];

/// 一族的核查结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardAssessment {
    pub family: &'static str,
    pub claimed: bool,
    pub safe_semantics: Option<&'static str>,
    pub unsafe_cited: bool,
    pub downgrade: Option<String>,
}

fn hit(markers: &[&str], hay: &str) -> bool {
    markers.iter().any(|m| hay.contains(m))
}

/// 定性声称匹配（词边界——"rce" 不误配 "source"）。
fn claim_hit(markers: &[&str], hay: &str) -> bool {
    markers
        .iter()
        .any(|m| fiora_core::util::contains_word(hay, m))
}

/// 核查一族定性（统一判定优先级）：
/// 无声称/sink 不中 → 不动；论证了危险语义 → 保留；安全语义在场 → 降级；
/// 自明危险原语 → 保留；无据且该族启用无据降级 → 降级。
pub fn assess(
    fam: &GuardFamily,
    title: &str,
    impact: &str,
    description: &str,
    sink_symbol: &str,
    probe_shape: Option<&str>,
    file_context: &str,
) -> GuardAssessment {
    let judge_hay = format!("{title}\n{impact}\n{description}");
    let claimed = claim_hit(fam.claim_keywords, &judge_hay);
    let cited_hay = format!("{judge_hay}\n{file_context}");
    let safe_semantics = fam
        .safe_semantics
        .iter()
        .find(|(p, _)| cited_hay.contains(p))
        .map(|(_, s)| *s);
    let unsafe_cited = hit(fam.unsafe_citations, &cited_hay);
    let sink_hit = hit(
        fam.sink_markers,
        &format!("{} {}", sink_symbol, probe_shape.unwrap_or_default()).to_lowercase(),
    );
    let unsafe_sink = hit(
        fam.known_unsafe_sinks,
        &format!(
            "{} {}",
            sink_symbol.to_lowercase(),
            probe_shape.unwrap_or_default().to_lowercase()
        ),
    );

    let downgrade = if !claimed || !sink_hit || unsafe_cited {
        None
    } else if let Some(sem) = safe_semantics {
        // 安全语义在场（围栏/参数化/过滤器），未论证绕过 → 降级。
        // 即使 sink 名是自明危险原语：现场配了围栏就该降级。
        Some(format!(
            "[{}] 机械降级：sink 命中已知安全语义（{sem}），未见绕过论证",
            fam.label
        ))
    } else if unsafe_sink {
        None // 自明危险原语（裸 pickle.loads / Marshal.load）——保留。
    } else if fam.ungrounded_downgrade {
        Some(format!("[{}] 机械降级：定性未引用语义（无据）", fam.label))
    } else {
        None
    };

    GuardAssessment {
        family: fam.label,
        claimed,
        safe_semantics,
        unsafe_cited,
        downgrade,
    }
}

/// 扫描 `CVE-YYYY-NNNNN` 标记（已知洞消歧）。字符边界安全。
pub fn scan_cve_markers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (idx, _) in text.match_indices("CVE-") {
        let rest = &text[idx + 4..];
        let digits: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        let parts: Vec<&str> = digits.split('-').collect();
        if parts.len() == 2
            && parts[0].len() == 4
            && (4..=7).contains(&parts[1].len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        {
            let id = format!("CVE-{digits}");
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

/// 入库前的机械核查统一入口：五族语义降级 + 已知洞标注。
/// 幂等：已带相同标注的不重复追加。降级封顶 `cap`（CRITICAL → HIGH）。
pub fn apply_mechanical_review(f: &mut Finding, file_context: &str) -> Option<String> {
    let impact = f.impact.clone().unwrap_or_default();
    let mut notes = Vec::new();

    for fam in ALL_FAMILIES {
        let a = assess(
            fam,
            &f.title,
            &impact,
            &f.description,
            &f.sink_symbol,
            f.probe_shape.as_deref(),
            file_context,
        );
        if let Some(reason) = &a.downgrade {
            if f.severity == Severity::Critical {
                f.severity = fam.cap;
            }
            if !impact.contains(reason) {
                notes.push(format!("⚠️ 机械核查：{reason}"));
            }
        }
    }

    for cve in scan_cve_markers(&format!("{impact}\n{}\n{file_context}", f.description)) {
        let note = format!("⚠️ 已知洞消歧：sink 语境标注 {cve}（上游已编号，披露前消歧）");
        if !impact.contains(&cve) && !notes.iter().any(|n| n.contains(&cve)) {
            notes.push(note);
        }
    }

    if notes.is_empty() {
        return None;
    }
    let joined = notes.join("\n");
    let new_impact = if impact.is_empty() {
        joined.clone()
    } else {
        format!("{impact}\n{joined}")
    };
    f.impact = Some(new_impact);
    Some(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(title: &str, impact: &str, sink: &str, category: &str) -> Finding {
        Finding {
            id: "t-1".into(),
            slug: category.into(),
            title: title.into(),
            severity: Severity::Critical,
            category: category.into(),
            file: "a.py".into(),
            line: 1,
            end_line: None,
            sink_symbol: sink.into(),
            enclosing_fn: "f".into(),
            probe_shape: None,
            description: String::new(),
            impact: Some(impact.into()),
            preconditions: vec![],
            data_flow: None,
            evidence_ref: None,
            repro_pack: None,
            verdict: None,
            chain_ids: vec![],
            agent: None,
            verification: None,
        }
    }

    // ---- RCE 族（加载语义 + 无据降级 + 自明原语）----

    #[test]
    fn rce_via_weights_only_true_is_downgraded() {
        // 实战教训：torch.load(weights_only=True) 被断言"可升 RCE"。
        let a = assess(
            &RCE,
            "权重加载可 RCE",
            "可实现远程代码执行",
            "加载 .bin 权重",
            "torch.load",
            Some("_load_pt_file"),
            "return torch.load(bin_file, map_location=\"cpu\", weights_only=True)",
        );
        assert!(a.claimed && !a.unsafe_cited);
        assert!(a.downgrade.is_some(), "weights_only=True 命中安全表应降级");
    }

    #[test]
    fn raw_pickle_rce_is_kept() {
        let a = assess(
            &RCE,
            "PickleWrapper 内网 RCE",
            "裸 pickle.loads，无白名单，一帧即 RCE",
            "msgpack 解包",
            "pickle.loads",
            None,
            "return pickle.loads(obj.data)",
        );
        assert!(a.unsafe_cited);
        assert!(a.downgrade.is_none(), "引用了危险语义应尊重原判");
    }

    #[test]
    fn command_injection_is_unaffected() {
        // 直接执行类 sink 不受本表约束（无加载语义可言）。
        let a = assess(
            &RCE,
            "命令注入 RCE",
            "可执行任意命令",
            "os.system(user)",
            "os.system",
            None,
            "os.system(req.q)",
        );
        assert!(a.claimed && a.downgrade.is_none());
    }

    #[test]
    fn ungrounded_loader_rce_is_downgraded() {
        let a = assess(
            &RCE,
            "反序列化可 RCE",
            "攻击者可远程执行代码",
            "解析数据",
            "deserialize",
            None,
            "obj = deserialize(payload)",
        );
        assert!(a.downgrade.is_some(), "无据 RCE 应降级");
    }

    #[test]
    fn unsafe_sink_kept_without_citation() {
        // 自明危险原语：裸名即危险，不逼 judge 写论证。
        let a = assess(
            &RCE,
            "Marshal RCE",
            "Marshal.load 反序列化即 RCE",
            "加载缓存",
            "Marshal.load",
            None,
            "Marshal.load(cache_bytes)",
        );
        assert!(!a.unsafe_cited && a.downgrade.is_none());
    }

    #[test]
    fn safe_filter_beats_unsafe_sink_name() {
        // 实战教训：已修白名单版被断言"继承绕过"——现场配了过滤器就降级。
        let a = assess(
            &RCE,
            "from_tensor RCE",
            "可实现远程代码执行",
            "反序列化",
            "SafeUnpickler",
            None,
            "SafeUnpickler(io.BytesIO(data)).load()",
        );
        assert!(a.downgrade.is_some(), "安全语义优先于 sink 名");
    }

    #[test]
    fn bypass_citation_is_respected() {
        let a = assess(
            &RCE,
            "from_tensor RCE",
            "SafeUnpickler 绕过可 RCE",
            "反序列化",
            "SafeUnpickler",
            None,
            "SafeUnpickler(io.BytesIO(data)).load()",
        );
        assert!(a.unsafe_cited && a.downgrade.is_none(), "论证了绕过应保留");
    }

    #[test]
    fn java_filter_downgraded_fastjson_kept() {
        let a = assess(
            &RCE,
            "反序列化 RCE",
            "可实现远程代码执行",
            "readObject 解析",
            "readObject",
            None,
            "ois.setObjectInputFilter(filter); ois.readObject()",
        );
        assert!(a.downgrade.is_some(), "JEP 290 在场应降级");
        let b = assess(
            &RCE,
            "Fastjson RCE",
            "autoType 绕过可 RCE",
            "parseObject 解析",
            "JSON.parseObject",
            None,
            "JSON.parseObject(payload)",
        );
        assert!(b.unsafe_cited && b.downgrade.is_none());
    }

    // ---- 其余四族 ----

    #[test]
    fn sqli_parameterized_downgraded_concat_kept() {
        let a = assess(
            &SQLI,
            "SQL 注入",
            "可注入数据库",
            "查询用户",
            "db.Query",
            None,
            r#"rows := db.Query("SELECT * FROM users WHERE id = ?", args...)"#,
        );
        assert!(a.downgrade.is_some(), "参数化在场应降级");
        let b = assess(
            &SQLI,
            "SQL 注入",
            "fmt.Sprintf 拼接进查询，可注入",
            "查询用户",
            "db.Query",
            None,
            "db.Query(sql, args...)",
        );
        assert!(b.unsafe_cited && b.downgrade.is_none(), "论证了拼接应保留");
    }

    #[test]
    fn ssrf_allowlist_downgraded_nocheck_kept() {
        let a = assess(
            &SSRF,
            "SSRF 漏洞",
            "可请求内网",
            "抓取图片",
            "http.Get",
            None,
            "if !is_safe_url(u) { return err }",
        );
        assert!(a.downgrade.is_some());
        let b = assess(
            &SSRF,
            "SSRF 漏洞",
            "无内网校验，可请求任意地址",
            "抓取图片",
            "http.Get",
            None,
            "http.Get(u)",
        );
        assert!(b.unsafe_cited && b.downgrade.is_none());
    }

    #[test]
    fn path_fence_present_downgraded_disabled_kept() {
        let a = assess(
            &PATH,
            "任意文件写",
            "可写任意路径",
            "保存上传",
            "save_image_to_path",
            None,
            "ensure_path_within_root(target, uploads_root)",
        );
        assert!(a.downgrade.is_some(), "围栏在场应降级");
        // 实战案例：围栏存在但未启用——judge 论证即保留。
        let b = assess(
            &PATH,
            "任意文件写",
            "围栏未启用（uploads_root 未传参），可写任意路径",
            "保存上传",
            "save_image_to_path",
            None,
            "ensure_path_within_root(target, uploads_root)",
        );
        assert!(b.unsafe_cited && b.downgrade.is_none());
    }

    #[test]
    fn template_sandbox_downgraded() {
        let a = assess(
            &TEMPLATE,
            "模板注入",
            "可执行模板表达式",
            "渲染页面",
            "render_template_string",
            None,
            "env = SandboxedEnvironment()",
        );
        assert!(a.downgrade.is_some());
    }

    #[test]
    fn non_rce_family_no_ungrounded_downgrade() {
        // 四族不做无据降级（无安全语义在场就不动）。
        let a = assess(
            &SQLI,
            "SQL 注入",
            "可注入数据库",
            "查询",
            "db.Query",
            None,
            "db.Query(q)",
        );
        assert!(a.claimed && a.downgrade.is_none());
    }

    // ---- 统一入口 ----

    #[test]
    fn apply_downgrades_caps_and_annotates() {
        let mut f = finding(
            "权重加载可 RCE",
            "可实现远程代码执行",
            "torch.load",
            "deser",
        );
        let note = apply_mechanical_review(&mut f, "torch.load(path, weights_only=True)");
        assert!(note.is_some());
        assert_eq!(f.severity, Severity::High, "CRITICAL 应封顶 HIGH");
        assert!(f.impact.clone().unwrap().contains("机械核查"));
        assert!(
            apply_mechanical_review(&mut f, "torch.load(path, weights_only=True)").is_none(),
            "幂等"
        );
    }

    #[test]
    fn apply_annotates_known_cve() {
        let mut f = finding("IPC 伪造", "伪造管理帧", "zmq_recv", "authz");
        let note = apply_mechanical_review(&mut f, "Reject TCP peers (CVE-2026-93034)").unwrap();
        assert!(note.contains("CVE-2026-93034"));
        assert_eq!(f.severity, Severity::Critical, "非降级不动定级");
    }

    #[test]
    fn cve_scanning_handles_unicode() {
        assert_eq!(
            scan_cve_markers("Reject TCP peers (CVE-2026-93034). See CVE-2025-10164"),
            vec!["CVE-2026-93034".to_string(), "CVE-2025-10164".to_string()]
        );
        assert!(scan_cve_markers("中文语境（CVE-2026-93034）也要能扫出")
            .contains(&"CVE-2026-93034".to_string()));
        assert!(scan_cve_markers("CVE-2026-93").is_empty(), "过短序号不匹配");
    }
}
