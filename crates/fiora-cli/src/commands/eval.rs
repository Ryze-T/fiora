//! `fiora eval` 命令组（DESIGN.md §2）。

use std::fs;
use std::path::Path;

use fiora_core::Ledger;

use crate::support::run_totals;

/// 成本口径：网关不回报金额时（cost=0 但确实消耗了 token）打印 n/a，
/// 不要把「没记账」写成「零成本」——那是把缺数据伪装成好消息。
fn fmt_cost(cost: f64, tokens: u64) -> String {
    if cost > 0.0 {
        format!("${cost:.3}")
    } else if tokens > 0 {
        format!("$n/a（{tokens} tokens，provider 未回报金额）")
    } else {
        "$0.000（零模型）".to_string()
    }
}

/// 每真洞成本：金额未知时同样是 n/a，不打印 $0.000/TP。
fn fmt_cost_per_tp(m: &fiora_eval::Metrics) -> String {
    if m.cost_usd > 0.0 && m.cost_per_true_positive.is_finite() {
        format!("${:.3}/TP", m.cost_per_true_positive)
    } else if m.tokens > 0 {
        format!("n/a/TP（{} tokens，provider 未回报金额）", m.tokens)
    } else {
        "$0.000/TP（零模型）".to_string()
    }
}

/// precision 口径：可测量才打印数字，否则打印 n/a + 原因。
fn fmt_precision(m: &fiora_eval::Metrics) -> String {
    match m.precision {
        Some(p) => format!("{:.0}%", p * 100.0),
        None => format!("n/a（{}）", m.precision_basis),
    }
}

pub(crate) fn cmd_eval(
    corpus_dir: &Path,
    model: Option<String>,
    thinking: &str,
    revalidate: bool,
    rule_only: bool,
    severity: &str,
    out: Option<&Path>,
) -> Result<(), String> {
    crate::support::validate_severity(severity)?;
    let cases = fiora_eval::load_corpus(corpus_dir)?;
    let mut all = Vec::new();
    // 模型/运行时故障不等于质量下降：单独记账，最终作废本次评分并退出非零，
    // 免得把「key 错了」读成「召回归零」。
    let mut hard_failures: Vec<String> = Vec::new();

    for (case_dir, case) in &cases {
        let root = case_dir.join("repo");
        println!("-- case: {} --", case.name);
        super::pipeline::cmd_scan(&root)?;

        // 下限门禁：规则通道候选 vs 基准（确定性、零模型）
        if rule_only {
            let ledger = Ledger::open(root.join(".fiora")).map_err(|e| e.to_string())?;
            let mut cands = Vec::new();
            for rel in ledger.list_files().map_err(|e| e.to_string())? {
                if let Some(rec) = ledger.load_file(&rel).map_err(|e| e.to_string())? {
                    cands.extend(rec.candidates);
                }
            }
            let m = fiora_eval::score_candidates(&case.expected, &cands);
            println!(
                "   rule-recall {:.0}% ({}/{}){}{} · missed: {:?}",
                m.recall * 100.0,
                m.matched,
                m.expected_total,
                if m.invisible_total > 0 {
                    format!(" · 规则不可见 {}", m.invisible_total)
                } else {
                    String::new()
                },
                if m.invisible_matched > 0 {
                    format!(
                        " · 警告：规则命中了 {} 条标注为不可见的期望（语料标注需修）",
                        m.invisible_matched
                    )
                } else {
                    String::new()
                },
                m.missed_files
            );
            all.push(m);
            continue;
        }

        super::pipeline::cmd_evidence(&root)?;
        // 评测范围默认 all：判定层把某条真阳性评成 MEDIUM 时，交付口（默认 high）
        // 会把它挡在账本外——记成漏报，测的其实是两个过滤器是否一致，不是能力。
        // 交付口径仍由 `run`/`report` 的 --severity 决定。
        // 单例隔离：一个案例的判定崩溃（模型/运行时故障）不中断整个回归——
        // 失败案例记零分并继续，故障面在结果里可见。
        if let Err(e) = super::pipeline::cmd_process(
            &root,
            None,
            model.clone(),
            Some(thinking),
            None,
            1,
            revalidate,
            None,
            severity,
        ) {
            eprintln!("   case failed (model/runtime, not a quality signal): {e}");
            hard_failures.push(format!("{}: {e}", case.name));
            all.push(fiora_eval::Metrics::zero_for(&case.expected));
            continue;
        }

        let ledger = Ledger::open(root.join(".fiora")).map_err(|e| e.to_string())?;
        let observed = crate::support::findings(&ledger).map_err(|e| format!("ledger: {e}"))?;
        // 证据 sink 映射：判定输出未携带 sink_symbol 时回落到证据骨架的权威坐标
        let mut evidence_sinks = std::collections::HashMap::new();
        for f in &observed {
            if let Some(eid) = &f.evidence_ref {
                if let Ok(Some(ev)) = ledger.load_evidence(eid) {
                    evidence_sinks.insert(eid.clone(), ev.sink.symbol.clone());
                }
            }
        }
        let (cost_usd, tokens) = run_totals(&ledger)?;
        let m = fiora_eval::score_with_evidence(
            &case.expected,
            &observed,
            cost_usd,
            tokens,
            &evidence_sinks,
        );
        println!(
            "   recall {:.0}% ({}/{}) · precision {}{} · {}{}{} · missed: {:?}",
            m.recall * 100.0,
            m.matched,
            m.expected_total,
            fmt_precision(&m),
            if m.false_positives > 0 {
                // 语料标注为界：判定层多报的真阳性也会落到 precision 分母里
                format!(" · 未标注判定 {} 条", m.false_positives)
            } else {
                String::new()
            },
            fmt_cost_per_tp(&m),
            if m.invisible_total > 0 {
                format!(
                    " · AI-only 期望 {}/{}",
                    m.invisible_matched, m.invisible_total
                )
            } else {
                String::new()
            },
            if m.invisible_matched > 0 && m.invisible_total == 0 {
                " · 警告：有期望标注为规则不可见却被规则命中"
            } else {
                ""
            },
            m.missed_files
        );
        all.push(m);
    }

    let total = fiora_eval::aggregate(&all);
    let label = if rule_only {
        "== floor gate (rule channel)"
    } else {
        "== corpus"
    };
    println!(
        "{}: recall {:.0}% ({}/{}) · precision {}{} · total {} · {}{}==",
        label,
        total.recall * 100.0,
        total.matched,
        total.expected_total,
        fmt_precision(&total),
        if total.false_positives > 0 {
            format!(" · 未标注判定 {} 条", total.false_positives)
        } else {
            String::new()
        },
        fmt_cost(total.cost_usd, total.tokens),
        fmt_cost_per_tp(&total),
        if total.invisible_total > 0 {
            format!(
                " · AI-only 期望 {}/{} · ",
                total.invisible_matched, total.invisible_total
            )
        } else {
            " ".to_string()
        }
    );
    if rule_only && total.invisible_matched > 0 {
        println!(
            "warning: {} 条期望标注为「规则不可见」却被规则命中——修语料标注（visible_to_rule）",
            total.invisible_matched
        );
    }
    if !hard_failures.is_empty() {
        eprintln!(
            "eval invalid: {} 个案例因模型/运行时故障未能判定（不是召回下降）",
            hard_failures.len()
        );
        for f in &hard_failures {
            eprintln!("  - {f}");
        }
        eprintln!("先修运行环境（模型 key / pi / 网络），再谈分数。");
        return Err(format!("{} hard failure(s)", hard_failures.len()));
    }
    if let Some(out) = out {
        let json = serde_json::to_string_pretty(&total).map_err(|e| e.to_string())?;
        fs::write(out, json).map_err(|e| e.to_string())?;
        println!("metrics: {}", out.display());
    }
    Ok(())
}
