//! Chain engine (DESIGN.md §5) — "deterministic pivots + composition", never
//! free-form imagination. Three composition patterns from the vuln-mining
//! methodology: dataflow chaining, privilege progression, capability stacking.

use fiora_core::{Chain, ChainPattern, ChainReach, ChainStep, Finding, Severity};

/// 传输层分类（A2）：链的每一跳都在某个传输面上——
/// HTTP 攻击通道只能打到 HTTP 面；裸 TCP/ZMQ 面需要同层立足点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    RawTcp,
    LocalFile,
    Benchmark,
}

pub fn transport_of(f: &Finding) -> Transport {
    let pre = f.preconditions.join(" ").to_ascii_lowercase();
    let text = format!("{} {} {}", f.category, f.title, pre).to_ascii_lowercase();
    if text.contains("benchmark") || text.contains("数据集") || text.contains("供应链") {
        Transport::Benchmark
    } else if text.contains("文件")
        || text.contains("覆写")
        || text.contains("file")
        || text.contains("path-traversal")
    {
        Transport::LocalFile
    } else if text.contains("zmq")
        || text.contains("裸")
        || text.contains("raw-tcp")
        || text.contains("tcp") && text.contains("回环")
    {
        Transport::RawTcp
    } else {
        Transport::Http
    }
}

/// 机制兼容：HTTP 攻击通道（SSRF 类）能 pivot 的是 HTTP 面；
/// RawTcp/Benchmark 面从 HTTP 通道不可直打 → transport-gap。
pub fn transport_compatible(pivot: &Finding, target: &Finding) -> bool {
    let (pt, tt) = (transport_of(pivot), transport_of(target));
    if pt == Transport::Http {
        matches!(tt, Transport::Http | Transport::LocalFile)
    } else {
        true // 本地立足点类 pivot 不受传输层限制
    }
}

/// Semantic groups used for composition.
fn group(f: &Finding) -> &'static str {
    match f.category.as_str() {
        // data/credential access
        "sqli" | "secrets-exposure" | "env-exposure" | "secret-in-log" | "path-traversal"
        | "secret-in-fallback" | "cross-tenant-id" | "idor" => "read",
        // execution / outbound capability
        "rce"
        | "cmdi"
        | "ssrf"
        | "open-redirect"
        | "unsafe-redirect"
        | "git-provider-url-injection" => "exec",
        // identity / authorization
        "auth-bypass" | "missing-auth" | "acl-check" | "jwt-handling" | "public-endpoint" => "auth",
        _ => "other",
    }
}

fn max_severity(a: Severity, b: Severity) -> Severity {
    if a.rank() >= b.rank() {
        a
    } else {
        b
    }
}

fn looks_read(f: &Finding) -> bool {
    let s = format!("{} {}", f.slug, f.description).to_ascii_lowercase();
    s.contains("read")
        || s.contains("get")
        || s.contains("list")
        || s.contains("query")
        || s.contains("idor")
}

fn looks_write(f: &Finding) -> bool {
    let s = format!("{} {}", f.slug, f.description).to_ascii_lowercase();
    s.contains("write")
        || s.contains("post")
        || s.contains("update")
        || s.contains("delete")
        || s.contains("create")
        || s.contains("admin")
}

/// Compose chains from true-positive findings. Deterministic and testable:
/// every chain maps to concrete pivots (shared category semantics + module).
pub fn compose_chains(findings: &[Finding]) -> Vec<Chain> {
    let tps: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.verdict.as_ref().map(|v| v.conclusion),
                Some(fiora_core::VerdictConclusion::TruePositive)
            )
        })
        .collect();

    let mut chains = Vec::new();
    for (i, a) in tps.iter().enumerate() {
        for b in tps.iter().skip(i + 1) {
            if let Some(chain) = pair_chain(a, b) {
                chains.push(chain);
            }
        }
    }
    chains
}

fn pair_chain(a: &Finding, b: &Finding) -> Option<Chain> {
    let (ga, gb) = (group(a), group(b));
    let (pattern, impact): (ChainPattern, String) = match (ga, gb) {
        // capability stacking: data/credential read + outbound/exec capability
        ("read", "exec") | ("exec", "read") => (
            ChainPattern::Stacking,
            "读取数据/凭据 + 可控外联/执行 = 横向移动或接管外部服务".to_string(),
        ),
        // dataflow chaining: leak/execute then abuse identity
        ("read", "auth") | ("exec", "auth") => (
            ChainPattern::Dataflow,
            "泄露/执行产物可作为身份凭证，进一步滥用鉴权面".to_string(),
        ),
        ("auth", "read") | ("auth", "exec") => (
            ChainPattern::Dataflow,
            "鉴权缺口放大既有数据/执行能力的影响面".to_string(),
        ),
        // privilege progression: low-priv read + write surface, both identity bugs
        ("auth", "auth")
            if (looks_read(a) && looks_write(b)) || (looks_write(a) && looks_read(b)) =>
        {
            (
                ChainPattern::Privilege,
                "低权读取 → 冒充/越权写入，权限递进".to_string(),
            )
        }
        _ => return None,
    };

    // A2 机制可达性：传输层不兼容 → 链标注 transport-gap（弱化而非删除）
    let (pivot, target) = if transport_of(a) == Transport::Http {
        (a, b)
    } else {
        (b, a)
    };
    let reach = if transport_compatible(pivot, target) {
        ChainReach::Direct
    } else {
        ChainReach::TransportGap
    };
    let sev = {
        let m = max_severity(a.severity, b.severity);
        // both high-end -> escalate the chain
        if a.severity.rank() >= 4 && b.severity.rank() >= 4 {
            Severity::Critical
        } else {
            m
        }
    };

    let title = format!("{} → {}", short_title(a), short_title(b));
    Some(Chain {
        id: fiora_core::id::chain_id(&title),
        title,
        pattern,
        steps: vec![
            ChainStep {
                finding_id: a.id.clone(),
                note: format!("起点：{}", a.title),
            },
            ChainStep {
                finding_id: b.id.clone(),
                note: format!("终点：{}", b.title),
            },
        ],
        impact: if reach == ChainReach::TransportGap {
            format!("{}（⚠ 传输层间隙：需另寻同层立足点桥接）", impact)
        } else {
            impact
        },
        severity: sev,
        reach,
    })
}

fn short_title(f: &Finding) -> String {
    let t = f.title.chars().take(40).collect::<String>();
    if f.title.chars().count() > 40 {
        format!("{t}…")
    } else {
        t
    }
}

/// Persist chains and link findings (additive union).
pub fn persist_chains(ledger: &fiora_core::Ledger, chains: &[Chain]) -> std::io::Result<usize> {
    let mut n = 0;
    for chain in chains {
        ledger.upsert_chain(chain.clone())?;
        for step in &chain.steps {
            ledger.link_chain(&step.finding_id, &chain.id)?;
        }
        n += 1;
    }
    Ok(n)
}
