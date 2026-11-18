//! `fiora-eval` — L5 evaluation layer (DESIGN.md §7).
//!
//! Regression corpus + scorer. Every harness change can be measured instead of
//! guessed: recall against known ground truth, precision of judged
//! true-positives, and cost per true positive (the number that decides whether
//! an audit is affordable). Corpus cases are plain directories: a `case.json`
//! manifest plus the vulnerable source tree.

use std::fs;
use std::path::Path;

use fiora_core::Finding;
use serde::{Deserialize, Serialize};

// ---------- corpus ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFinding {
    pub file: String,
    pub category: String,
    /// Optional tighter match: the probe shape / sink symbol token.
    #[serde(default)]
    pub sink_symbol: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    /// 规则通道在单点（单行/单文件）能否看见这条问题。
    ///
    /// `false` = 只有跨文件数据流/授权语义才能发现（如跨层 IDOR、路由挂载缺鉴权）。
    /// 这类期望**不计入规则下限分母**——否则门禁在拿规则去背它本来就看不见的题；
    /// 它们的分母是 AI 通道，用来量化「语义通道的边际价值」。
    #[serde(default = "visible_by_default")]
    pub visible_to_rule: bool,
}

fn visible_by_default() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub expected: Vec<ExpectedFinding>,
}

pub fn load_case(case_dir: &Path) -> Result<Case, String> {
    let manifest = case_dir.join("case.json");
    let text = fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("case.json: {e}"))
}

/// Load every `*/case.json` under a corpus root, sorted by name.
pub fn load_corpus(corpus_dir: &Path) -> Result<Vec<(std::path::PathBuf, Case)>, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir(corpus_dir).map_err(|e| format!("corpus: {e}"))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() && path.join("case.json").exists() {
            let case = load_case(&path)?;
            out.push((path, case));
        }
    }
    out.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    Ok(out)
}

// ---------- matching ----------

/// A finding matches an expectation when the file agrees and either the
/// category agrees (等价词表 ∪ 族 ∪ 超族) or the expectation carries a sink token
/// that the finding names **exactly**.
///
/// 为什么允许「类别不同但同一 sink + 同一关注面」：TP 的身份锚点是
/// `sink_symbol + enclosing_fn`（账本契约），类别只是词表选择。同文件、同 sink
/// 的判定结论就是同一处代码——把 `broken-access-control` 与 `session-exposure`
/// 记成漏报，测的是词表运气，不是能力。跨关注面（越权 vs SQLi）仍不互相顶替。
pub fn matches(finding: &Finding, expected: &ExpectedFinding) -> bool {
    if finding.file != expected.file {
        return false;
    }
    let sink_ok = match &expected.sink_symbol {
        Some(tok) => {
            finding.sink_symbol.contains(tok.as_str())
                || finding
                    .probe_shape
                    .as_deref()
                    .map(|p| p.contains(tok.as_str()))
                    .unwrap_or(false)
                // 调用名一致即同一处调用：`c.Run` 与 `(*exec.Cmd).Run` 是同一行的
                // 同一个调用，差别只是语料写变量名、判定层写声明类型。
                || tok.contains('.') && sink_tail(tok) == sink_tail(&finding.sink_symbol)
        }
        None => true,
    };
    if !sink_ok {
        return false;
    }
    category_equivalent(&finding.category, &expected.category)
        || concern(&finding.category) == concern(&expected.category)
}

/// sink 名的最后一段：`(*exec.Cmd).Run` 与 `c.Run` 都是 `Run`。
///
/// sink 的身份是「调用了谁」，不是 owner 怎么拼：变量名（`c`）、声明类型
/// （`(*exec.Cmd)`）、包名（`exec`）在语料、判定输出、证据骨架三处本来就不一致。
/// 只用最后一段做区分，前缀仍走 contains，因此 `db.Raw` 与 `db.Exec` 依旧不同。
fn sink_tail(s: &str) -> &str {
    s.rsplit(['.', ':']).next().unwrap_or(s).trim()
}

/// 粗关注面：允许「同文件 + sink 精确一致」时跨词表命中，但只跨在同一个关注面内
/// （access/session/exposure 都是"这一处没守住"），不跨到注入/执行面——
/// 否则同 sink 上的 SQLi 结论会把一条越权期望吃掉。
fn concern(s: &str) -> &'static str {
    let n = norm(s);
    const ACCESS: &[&str] = &[
        "auth",
        "access",
        "session",
        "permission",
        "privilege",
        "exposure",
        "leak",
        "disclosure",
        "idor",
        // 多租户隔离是授权面的一种：租户身份取自请求头 vs 会话，结论写成
        // tenant-isolation-bypass 或 idor 是同一个漏洞的不同叫法
        "tenant",
    ];
    const INJECTION: &[&str] = &["sqli", "xss", "inject", "cmdi", "ssti", "xxe"];
    const EXECUTION: &[&str] = &["rce", "eval", "codeexecution", "deser", "deserial"];
    if ACCESS.iter().any(|k| n.contains(k)) {
        "access"
    } else if INJECTION.iter().any(|k| n.contains(k)) {
        "injection"
    } else if EXECUTION.iter().any(|k| n.contains(k)) {
        "execution"
    } else {
        "other"
    }
}

// ---------- rule-channel scoring (the FLOOR gate) ----------

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

/// 同族漏洞类别别名（下限匹配语义：同类叫法互通）。
/// 子串命中任一族成员即归族——`floor-const-credential` 归 hardcoded 族，
/// `floor-route-no-auth-flask` 归 auth 族。
fn family(s: &str) -> String {
    let n = norm(s);
    for fam in [
        // 授权面单独一族：判定层会写 missing-authorization / broken-access-control /
        // idor，基准写的是其中任一种词，不能让词表选择吃掉一个真阳性。
        &[
            "authz",
            "authorization",
            "accesscontrol",
            "permission",
            "privilegeescalation",
            "idor",
        ][..],
        &[
            "auth",
            "unauth",
            "missingauth",
            "authbypass",
            "aclcheck",
            "noauth",
            "route",
        ][..],
        &["deser", "deserialization", "readobject", "unserialize"][..],
        &[
            "hardcoded",
            "secretsexposure",
            "credential",
            "secret",
            "token",
            "apikey",
            "password",
        ][..],
        &["rce", "cmdi", "commandinjection", "codeexecution", "eval"][..],
        &["traversal", "pathtraversal", "lfi", "fileread"][..],
        &["sqli", "sqlinjection", "inject"][..],
        &["ssrf", "requestforgery"][..],
        &[
            "tls",
            "insecuressl",
            "weakcrypto",
            "insecuretls",
            "certificateverification",
            "skipverify",
        ][..],
    ] {
        if fam.iter().any(|f| n.contains(f)) {
            return fam[0].to_string();
        }
    }
    n
}

/// 超族（末位兜底）：反序列化/SSTI 是 RCE 的实现机制，ground truth 写 rce、
/// 判定层归 deser/ssti 时应互通——测「找到这类问题了吗」，不罚词表选择。
fn superfamily(s: &str) -> String {
    let f = family(s);
    match f.as_str() {
        "rce" | "deser" => "rce-mega".to_string(),
        // 鉴权/授权是同一面：缺鉴权、缺鉴权中间件、越权都算「这一处没守住」
        "auth" | "authz" => "auth-mega".to_string(),
        other => other.to_string(),
    }
}

/// 两套评分器共用的类别等价判定：归一化子串 ∪ 同族 ∪ 超族。
fn category_equivalent(a: &str, b: &str) -> bool {
    let (na, nb) = (norm(a), norm(b));
    na.contains(&nb)
        || nb.contains(&na)
        || family(a) == family(b)
        || superfamily(a) == superfamily(b)
}

/// 下限门禁：规则通道候选 vs **规则可见**基准期望。粗匹配（归一化类别子串），
/// 度量「同类工具能挖的规则面是否漏」——不依赖模型，确定性可 CI。
///
/// 规则不可见的期望不进分母（跑到规则通道的分母上只会给出假失败）；
/// 若规则居然命中了它们，会记 `invisible_matched`——那是语料标注错了，要修语料。
pub fn score_candidates(
    expected: &[ExpectedFinding],
    candidates: &[fiora_core::Candidate],
) -> Metrics {
    let mut matched_flags = vec![false; expected.len()];
    for (i, exp) in expected.iter().enumerate() {
        for c in candidates {
            if c.file != exp.file {
                continue;
            }
            // 匹配语义：与 finding 通道同源（归一化子串 ∪ 同族 ∪ 超族）
            let cat_ok = category_equivalent(&c.matcher_id, &exp.category);
            let sink_ok = match &exp.sink_symbol {
                Some(tok) => {
                    c.snippet.contains(tok.as_str())
                        || c.note
                            .as_deref()
                            .map(|n| n.contains(tok.as_str()))
                            .unwrap_or(false)
                }
                None => true,
            };
            if cat_ok && sink_ok {
                matched_flags[i] = true;
            }
        }
    }
    let visible_total = expected.iter().filter(|e| e.visible_to_rule).count();
    let invisible_total = expected.len() - visible_total;
    let matched = expected
        .iter()
        .zip(&matched_flags)
        .filter(|(e, m)| e.visible_to_rule && **m)
        .count();
    let invisible_matched = expected
        .iter()
        .zip(&matched_flags)
        .filter(|(e, m)| !e.visible_to_rule && **m)
        .count();
    Metrics {
        expected_total: visible_total,
        matched,
        missed: visible_total - matched,
        false_positives: 0,
        recall: if visible_total == 0 {
            1.0
        } else {
            matched as f64 / visible_total as f64
        },
        // 候选未经判定，精确率无从测量——报 n/a，不编一个 1.0。
        precision: None,
        precision_basis: "规则候选未判定，precision 只在判定通道有意义".to_string(),
        invisible_total,
        invisible_matched,
        cost_usd: 0.0,
        tokens: 0,
        cost_per_true_positive: 0.0,
        missed_files: expected
            .iter()
            .zip(&matched_flags)
            .filter(|(e, m)| e.visible_to_rule && !**m)
            .map(|(e, _)| format!("{}:{}", e.file, e.category))
            .collect(),
    }
}

// ---------- scoring ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub expected_total: usize,
    pub matched: usize,
    pub missed: usize,
    /// Judged true-positives that match no expectation (eval-time false alarms).
    pub false_positives: usize,
    /// recall = matched / expected_total
    pub recall: f64,
    /// precision = matched / (matched + false_positives)。
    /// 未判定通道（规则候选）为 `None` = n/a，不伪造数字。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precision: Option<f64>,
    /// precision 的口径说明（measured / n/a（候选未判定）…）
    pub precision_basis: String,
    /// 规则通道视角看不见的期望条数（语义通道才可能发现）
    pub invisible_total: usize,
    /// 其中被规则通道命中的条数——非 0 说明 visible_to_rule 标注错了
    pub invisible_matched: usize,
    pub cost_usd: f64,
    pub tokens: u64,
    /// cost_usd / matched (f64::INFINITY serializes as null via custom care below)
    pub cost_per_true_positive: f64,
    pub missed_files: Vec<String>,
}

impl Metrics {
    /// 单例隔离用：案例判定崩溃（模型/运行时故障）时记零分，不中断整个回归。
    pub fn zero_for(expected: &[ExpectedFinding]) -> Metrics {
        Metrics {
            expected_total: expected.len(),
            matched: 0,
            missed: expected.len(),
            false_positives: 0,
            recall: 0.0,
            precision: Some(0.0),
            precision_basis: "measured".to_string(),
            invisible_total: expected.iter().filter(|e| !e.visible_to_rule).count(),
            invisible_matched: 0,
            cost_usd: 0.0,
            tokens: 0,
            cost_per_true_positive: f64::INFINITY,
            missed_files: expected
                .iter()
                .map(|e| format!("{}:{}", e.file, e.category))
                .collect(),
        }
    }
}

/// Score observed findings against ground truth. `cost` is the total spend of
/// the run that produced them.
pub fn score(
    expected: &[ExpectedFinding],
    observed: &[Finding],
    cost_usd: f64,
    tokens: u64,
) -> Metrics {
    score_with_evidence(
        expected,
        observed,
        cost_usd,
        tokens,
        &std::collections::HashMap::new(),
    )
}

/// 带证据 sink 回落的全量打分：TP 的 sink_symbol 为空时（判定输出未携带），
/// 用其 evidence_ref 指向的证据骨架 sink（确定性预装配的权威坐标）替代匹配。
pub fn score_with_evidence(
    expected: &[ExpectedFinding],
    observed: &[Finding],
    cost_usd: f64,
    tokens: u64,
    evidence_sinks: &std::collections::HashMap<String, String>,
) -> Metrics {
    let mut matched_flags = vec![false; expected.len()];
    let mut judged_tp_flags = vec![false; observed.len()];

    for (i, exp) in expected.iter().enumerate() {
        for (j, f) in observed.iter().enumerate() {
            if !is_judged_tp(f) {
                continue;
            }
            // sink 回落：finding.sink_symbol 空 → 证据骨架的 sink 符号
            let mut owned;
            let mut f_ref = f;
            if f.sink_symbol.is_empty() {
                if let Some(sink) = f.evidence_ref.as_ref().and_then(|e| evidence_sinks.get(e)) {
                    owned = f.clone();
                    owned.sink_symbol = sink.clone();
                    f_ref = &owned;
                }
            }
            if matches(f_ref, exp) {
                matched_flags[i] = true;
                judged_tp_flags[j] = true;
            }
        }
    }
    let matched = matched_flags.iter().filter(|m| **m).count();
    let missed = expected.len() - matched;

    let judged_tp_total = observed.iter().filter(|f| is_judged_tp(f)).count();
    let false_positives = judged_tp_flags
        .iter()
        .zip(observed)
        .filter(|(flag, f)| !**flag && is_judged_tp(f))
        .count();

    let recall = if expected.is_empty() {
        1.0
    } else {
        matched as f64 / expected.len() as f64
    };
    // precision 口径：分母是判为 TP 的发现总数，分子是命中任一期望的发现数
    // （一个发现匹配多条同族期望不得推高 precision 超 100%）。
    let matched_findings = judged_tp_flags.iter().filter(|m| **m).count();
    let precision = if judged_tp_total == 0 {
        0.0
    } else {
        matched_findings as f64 / judged_tp_total as f64
    };
    let invisible_total = expected.iter().filter(|e| !e.visible_to_rule).count();
    let invisible_matched = expected
        .iter()
        .zip(&matched_flags)
        .filter(|(e, m)| !e.visible_to_rule && **m)
        .count();
    let cost_per_true_positive = if matched == 0 {
        f64::INFINITY
    } else {
        cost_usd / matched as f64
    };

    Metrics {
        expected_total: expected.len(),
        matched,
        missed,
        false_positives,
        recall,
        precision: Some(precision),
        precision_basis: "measured（判定通道 TP vs 基准）".to_string(),
        invisible_total,
        invisible_matched,
        cost_usd,
        tokens,
        cost_per_true_positive,
        missed_files: expected
            .iter()
            .zip(matched_flags)
            .filter(|(_, m)| !*m)
            .map(|(e, _)| format!("{}:{}", e.file, e.category))
            .collect(),
    }
}

fn is_judged_tp(f: &Finding) -> bool {
    matches!(
        f.verdict.as_ref().map(|v| v.conclusion),
        Some(fiora_core::VerdictConclusion::TruePositive)
    )
}

/// Aggregate per-case metrics into one corpus-level number (micro average).
pub fn aggregate(all: &[Metrics]) -> Metrics {
    let expected_total = all.iter().map(|m| m.expected_total).sum();
    let matched = all.iter().map(|m| m.matched).sum();
    let false_positives = all.iter().map(|m| m.false_positives).sum();
    let cost_usd: f64 = all.iter().map(|m| m.cost_usd).sum();
    let tokens = all.iter().map(|m| m.tokens).sum();
    let missed_files: Vec<String> = all.iter().flat_map(|m| m.missed_files.clone()).collect();
    let invisible_total: usize = all.iter().map(|m| m.invisible_total).sum();
    let invisible_matched: usize = all.iter().map(|m| m.invisible_matched).sum();
    let mut total = score(
        &vec![
            ExpectedFinding {
                file: String::new(),
                category: String::new(),
                sink_symbol: None,
                severity: None,
                visible_to_rule: true,
            };
            expected_total
        ],
        &[],
        cost_usd,
        tokens,
    );
    // overwrite with micro-averaged numbers
    total.expected_total = expected_total;
    total.matched = matched;
    total.missed = expected_total - matched;
    total.false_positives = false_positives;
    total.recall = if expected_total == 0 {
        1.0
    } else {
        matched as f64 / expected_total as f64
    };
    // precision 只在判定通道可测：全部案例都没测量 → n/a（不拿候选冒充）。
    if all.iter().all(|m| m.precision.is_none()) {
        total.precision = None;
        total.precision_basis = "仅规则候选，未做判定".to_string();
    } else {
        let judged: Vec<&Metrics> = all.iter().filter(|m| m.precision.is_some()).collect();
        let judged_matched: usize = judged.iter().map(|m| m.matched).sum();
        let judged_tp: usize = judged.iter().map(|m| m.matched + m.false_positives).sum();
        total.precision = Some(if judged_tp == 0 {
            0.0
        } else {
            judged_matched as f64 / judged_tp as f64
        });
        total.precision_basis = "measured（判定通道 TP vs 基准）".to_string();
    }
    total.invisible_total = invisible_total;
    total.invisible_matched = invisible_matched;
    total.cost_per_true_positive = if matched == 0 {
        f64::INFINITY
    } else {
        cost_usd / matched as f64
    };
    total.missed_files = missed_files;
    total
}
