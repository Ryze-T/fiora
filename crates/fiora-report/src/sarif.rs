//! SARIF 2.1.0 export — the machine-readable door of the report.
//!
//! CI and IDEs speak SARIF; without it the audit result is stuck inside HTML.
//! One result per *confirmed-or-open* finding (false-positive rejects are not
//! issues and are dropped), with stable fingerprints so a finding keeps its
//! identity across runs even when lines move.

use serde_json::{json, Map, Value};

use crate::{ReportData, Severity};

/// SARIF `level` for a severity. Critical/High fail builds, Medium warns,
/// everything else is informational.
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}

/// GitHub code-scanning `security-severity` (CVSS-like score) per severity.
fn security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        _ => "0.0",
    }
}

/// `CWE-89` → `external/cwe/cwe-089`（GitHub 认这个标签形态）。
fn cwe_tag(cwe: &str) -> Option<String> {
    let n: u32 = cwe.strip_prefix("CWE-")?.parse().ok()?;
    Some(format!("external/cwe/cwe-{n:03}"))
}

/// Render the ledger as a SARIF log. Deterministic: findings are sorted by
/// (file, line, id) so two runs of the same ledger produce identical bytes.
pub fn render_sarif(d: &ReportData) -> String {
    let mut findings: Vec<&fiora_core::Finding> = d
        .findings
        .iter()
        .filter(|f| {
            !matches!(
                f.verdict.as_ref().map(|v| v.conclusion),
                Some(fiora_core::VerdictConclusion::FalsePositive)
            )
        })
        .collect();
    findings.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.id.as_str()).cmp(&(b.file.as_str(), b.line, b.id.as_str()))
    });

    // rules[] — one per category, in first-use order after sorting.
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_index: Map<String, Value> = Map::new();
    for f in &findings {
        if rule_index.contains_key(&f.category) {
            continue;
        }
        rule_index.insert(f.category.clone(), json!(rules.len()));
        let mut props = Map::new();
        let cwe = fiora_core::family::cwe_from_category(f);
        // GitHub Code Scanning 靠 `external/cwe/cwe-NNN` 标签做 CWE 归类，
        // 只写自定义 cwe 字段是收不到映射的。
        let mut tags: Vec<String> = vec!["security".into(), "fiora".into()];
        if let Some(tag) = cwe.and_then(cwe_tag) {
            tags.push(tag);
        }
        props.insert("tags".into(), json!(tags));
        props.insert(
            "security-severity".into(),
            json!(security_severity(f.severity)),
        );
        if let Some(cwe) = cwe {
            props.insert("cwe".into(), json!(cwe));
        }
        rules.push(json!({
            "id": f.category,
            "name": f.category,
            "shortDescription": { "text": format!("Fiora category: {}", f.category) },
            "fullDescription": { "text": "Finding category judged by the Fiora audit pipeline (rule channel + AI judge + revalidation)." },
            "defaultConfiguration": { "level": sarif_level(f.severity) },
            "properties": Value::Object(props),
        }));
    }

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut props = Map::new();
            props.insert("severity".into(), json!(format!("{:?}", f.severity)));
            props.insert(
                "family".into(),
                json!(format!("{:?}", fiora_core::family::classify(f))),
            );
            // result 上给启发式 CWE 并标注来源，避免把「描述里出现代码执行」
            // 当成确定的 CWE 归类。
            match fiora_core::family::cwe_from_category(f) {
                Some(cwe) => {
                    props.insert("cwe".into(), json!(cwe));
                }
                None => {
                    if let Some(hint) = fiora_core::family::cwe_for(f) {
                        props.insert("cweHint".into(), json!(hint));
                    }
                }
            }
            if let Some(v) = &f.verdict {
                props.insert("verdict".into(), json!(format!("{:?}", v.conclusion)));
                props.insert("verdictReason".into(), json!(v.reasoning));
            }
            props.insert("sinkSymbol".into(), json!(f.sink_symbol));
            props.insert("enclosingFn".into(), json!(f.enclosing_fn));
            if let Some(ev) = &f.evidence_ref {
                props.insert("evidenceRef".into(), json!(ev));
            }
            if !f.chain_ids.is_empty() {
                props.insert("chainIds".into(), json!(f.chain_ids));
            }
            if let Some(ver) = &f.verification {
                props.insert("verification".into(), json!(ver.verdict));
            }

            let mut region = json!({ "startLine": f.line });
            if let Some(end) = f.end_line {
                region["endLine"] = json!(end);
            }
            let mut location = json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": f.file },
                    "region": region,
                }
            });
            // 汇点函数名让 IDE/评审人直接定位到被污染的构造
            location["logicalLocations"] = json!([{
                "fullyQualifiedName": f.enclosing_fn,
                "kind": "function",
                "purpose": "sink",
            }]);

            json!({
                "ruleId": f.category,
                "ruleIndex": rule_index.get(&f.category).cloned().unwrap_or(json!(0)),
                "level": sarif_level(f.severity),
                "message": { "text": message_for(f) },
                "locations": [location],
                "partialFingerprints": { "fioraFindingId/v1": f.id },
                "properties": Value::Object(props),
            })
        })
        .collect();

    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "fiora",
                    "informationUri": "https://github.com/Ryze-T/fiora",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": true,
                "startTimeUtc": d.generated_at,
                "workingDirectory": { "uri": d.repo_label },
            }],
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".to_string())
}

fn message_for(f: &fiora_core::Finding) -> String {
    let mut m = format!("{} — {}", f.title, f.description);
    if let Some(impact) = &f.impact {
        m.push_str(&format!("\n\n影响：{impact}"));
    }
    if let Some(r) = &f.verdict {
        m.push_str(&format!("\n\n判定：{:?}（{}）", r.conclusion, r.reasoning));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Coverage, ReportData};
    use std::collections::HashMap;

    fn data(findings: Vec<fiora_core::Finding>) -> ReportData {
        ReportData {
            project: "demo".into(),
            repo_label: "demo@abc123".into(),
            method: "规则扫描 + AI 深审".into(),
            agent_label: "Fiora v0.2.0 · 模型 X（pi 会话驱动）".into(),
            generated_at: "2026-03-04T05:06:07Z".into(),
            scope: "全仓代码审计".into(),
            tech_tags: vec![],
            findings,
            chains: vec![],
            evidence: vec![],
            snippets: HashMap::new(),
            coverage: Coverage {
                files_tracked: 1,
                files_analyzed: 1,
                files_skipped: 0,
                files_pending: 0,
                candidates_rule: 1,
                candidates_semantic: 0,
                surface_entries: 1,
            },
            surface: vec![],
            method_notes: vec![],
            cost_summary: None,
        }
    }

    fn finding(id: &str, cat: &str, sev: Severity, line: u32) -> fiora_core::Finding {
        fiora_core::Finding {
            id: id.into(),
            slug: cat.into(),
            title: format!("{cat} finding"),
            severity: sev,
            category: cat.into(),
            file: "a.go".into(),
            line,
            end_line: None,
            sink_symbol: "db.Query".into(),
            enclosing_fn: "handler".into(),
            probe_shape: None,
            description: "user input reaches the sink".into(),
            impact: None,
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

    #[test]
    fn sarif_is_valid_and_maps_severity_to_levels() {
        let d = data(vec![
            finding("f1", "sqli", Severity::High, 9),
            finding("f2", "ssrf", Severity::Low, 3),
        ]);
        let v: Value = serde_json::from_str(&render_sarif(&d)).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "fiora");
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        // 排序：文件内按行号（3 在前）
        assert_eq!(results[0]["ruleId"], "ssrf");
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[1]["partialFingerprints"]["fioraFindingId/v1"], "f1");
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "a.go"
        );
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["region"]["startLine"],
            9
        );
        // GitHub Code Scanning 的 CWE 归类靠 external/cwe 标签，不是自定义字段
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        let sqli_rule = rules.iter().find(|r| r["id"] == "sqli").unwrap();
        assert!(
            sqli_rule["properties"]["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "external/cwe/cwe-089"),
            "sqli 规则带 CWE-89 标签: {sqli_rule}"
        );
        assert_eq!(sqli_rule["properties"]["security-severity"], "8.0");
    }

    #[test]
    fn sarif_drops_false_positives_and_is_deterministic() {
        let mut fp = finding("fp", "sqli", Severity::High, 1);
        fp.verdict = Some(fiora_core::Verdict {
            conclusion: fiora_core::VerdictConclusion::FalsePositive,
            confidence: fiora_core::Confidence::High,
            evidence_ref: None,
            rebuttals: fiora_core::RebuttalAnswers {
                parameterized: Some(true),
                reachable: None,
                business_method: None,
                allowlisted: None,
                user_input_controlled: None,
                protected_by_guard: None,
                notes: String::new(),
            },
            reasoning: "parameterized".into(),
        });
        let d = data(vec![finding("f1", "sqli", Severity::Medium, 7), fp]);
        let a = render_sarif(&d);
        let b = render_sarif(&d);
        assert_eq!(a, b, "同一账本必须渲染出相同字节");
        let v: Value = serde_json::from_str(&a).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "误报否决不进 SARIF");
        assert_eq!(results[0]["level"], "warning");
    }
}
