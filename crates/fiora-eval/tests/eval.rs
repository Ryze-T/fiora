//! L5 scorer tests: matching semantics, recall/precision/cost math, corpus IO.

use fiora_core::{Confidence, Finding, RebuttalAnswers, Severity, Verdict, VerdictConclusion};
use fiora_eval::{aggregate, load_corpus, matches, score, ExpectedFinding};

fn finding(file: &str, category: &str, sink: &str, tp: bool) -> Finding {
    Finding {
        id: format!("f-{file}-{category}-{sink}"),
        slug: category.to_string(),
        title: format!("{category} at {file}"),
        severity: Severity::High,
        category: category.to_string(),
        file: file.to_string(),
        line: 1,
        end_line: None,
        sink_symbol: sink.to_string(),
        enclosing_fn: "fn".to_string(),
        probe_shape: Some(format!("{sink}(")),
        description: "d".to_string(),
        impact: None,
        preconditions: vec![],
        data_flow: None,
        evidence_ref: None,
        repro_pack: None,
        verdict: Some(Verdict {
            conclusion: if tp {
                VerdictConclusion::TruePositive
            } else {
                VerdictConclusion::FalsePositive
            },
            confidence: Confidence::High,
            evidence_ref: None,
            reasoning: "r".to_string(),
            rebuttals: RebuttalAnswers {
                parameterized: Some(false),
                reachable: Some(true),
                business_method: Some(false),
                allowlisted: Some(false),
                user_input_controlled: Some(true),
                protected_by_guard: Some(false),
                notes: String::new(),
            },
        }),
        chain_ids: vec![],
        agent: None,
        verification: None,
    }
}

fn exp(file: &str, category: &str, sink: Option<&str>) -> ExpectedFinding {
    ExpectedFinding {
        file: file.to_string(),
        category: category.to_string(),
        sink_symbol: sink.map(str::to_string),
        severity: None,
        visible_to_rule: true,
    }
}

#[test]
fn matching_respects_file_category_and_sink_token() {
    let f = finding("api/vuln.go", "sqli", "db.Exec", true);
    assert!(matches(&f, &exp("api/vuln.go", "sqli", Some("db.Exec"))));
    assert!(matches(&f, &exp("api/vuln.go", "sqli", None)));
    assert!(
        !matches(&f, &exp("api/vuln.go", "sqli", Some("db.Raw"))),
        "wrong sink token"
    );
    assert!(!matches(&f, &exp("api/other.go", "sqli", None)));
    assert!(!matches(&f, &exp("api/vuln.go", "ssrf", None)));
}

#[test]
fn matching_accepts_category_vocabulary_variants() {
    // 判定层的类别词表与 ground truth 用词不必逐字相等：归一化/同族即可
    // （auth_bypass ≡ auth，反序列化族别名互通），与规则通道语义一致。
    let f = finding("app.js", "auth_bypass", "router.post", true);
    assert!(matches(&f, &exp("app.js", "auth", None)));
    let d = finding("io/x.py", "insecure-deserialization", "pickle.loads", true);
    assert!(matches(&d, &exp("io/x.py", "deser", Some("pickle.loads"))));
    // 但不同族仍不得互配
    assert!(!matches(&d, &exp("io/x.py", "ssrf", None)));
}

#[test]
fn score_computes_recall_precision_and_cost_per_tp() {
    let expected = vec![
        exp("a.go", "sqli", Some("db.Exec")),
        exp("b.go", "ssrf", Some("http.Get")),
        exp("c.go", "missing-auth", None), // will be missed
    ];
    let observed = vec![
        finding("a.go", "sqli", "db.Exec", true),     // match
        finding("b.go", "ssrf", "http.Get", true),    // match
        finding("x.go", "rce", "exec.Command", true), // judged TP but no ground truth -> FP in eval
        finding("y.go", "sqli", "db.Raw", false),     // judged FP, ignored
    ];
    let m = score(&expected, &observed, 12.0, 6200);

    assert_eq!(m.matched, 2);
    assert_eq!(m.missed, 1);
    assert_eq!(m.false_positives, 1);
    assert!((m.recall - 2.0 / 3.0).abs() < 1e-9);
    assert!((m.precision.unwrap() - 2.0 / 3.0).abs() < 1e-9);
    assert!(
        (m.cost_per_true_positive - 6.0).abs() < 1e-9,
        "12 USD / 2 TP"
    );
    assert_eq!(m.missed_files, vec!["c.go:missing-auth".to_string()]);
    assert_eq!(m.tokens, 6200);
}

#[test]
fn perfect_and_zero_runs_degrade_gracefully() {
    let expected = vec![exp("a.go", "sqli", None)];
    let perfect = score(
        &expected,
        &[finding("a.go", "sqli", "db.Exec", true)],
        1.0,
        10,
    );
    assert_eq!((perfect.recall, perfect.precision), (1.0, Some(1.0)));
    assert!((perfect.cost_per_true_positive - 1.0).abs() < 1e-9);

    let zero = score(&expected, &[], 5.0, 100);
    assert_eq!(zero.recall, 0.0);
    assert!(
        zero.cost_per_true_positive.is_infinite(),
        "no TP found, cost unbounded"
    );
}

#[test]
fn aggregate_micro_averages_corpus_metrics() {
    let a = score(
        &[exp("a.go", "sqli", None), exp("b.go", "ssrf", None)],
        &[finding("a.go", "sqli", "db.Exec", true)],
        4.0,
        100,
    );
    let b = score(
        &[exp("c.go", "rce", None)],
        &[finding("c.go", "rce", "exec.Command", true)],
        2.0,
        50,
    );
    let total = aggregate(&[a, b]);
    assert_eq!(total.expected_total, 3);
    assert_eq!(total.matched, 2);
    assert!((total.recall - 2.0 / 3.0).abs() < 1e-9);
    assert_eq!(total.precision, Some(1.0));
    assert!((total.cost_usd - 6.0).abs() < 1e-9);
    assert!((total.cost_per_true_positive - 3.0).abs() < 1e-9);
}

#[test]
fn bundled_corpus_loads() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let cases = load_corpus(&corpus).unwrap();
    assert!(cases.len() >= 25, "benchmark corpus (got {})", cases.len());
    let go = cases.iter().find(|c| c.1.name == "go-webapp").unwrap();
    assert_eq!(go.1.expected.len(), 3);
    assert!(go.0.join("repo").is_dir(), "case ships its source tree");
}

#[test]
fn corpus_integrity_and_floor_matcher() {
    // 语料完整性 + 下限匹配器单测（CI 门禁的纯逻辑部分，零外部依赖）
    use fiora_core::{Candidate, CandidateChannel};
    use fiora_eval::{load_corpus, score_candidates, ExpectedFinding};

    let corpus = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let cases = load_corpus(&corpus).expect("corpus loads");
    assert!(
        cases.len() >= 25,
        "corpus must carry the benchmark cases (got {})",
        cases.len()
    );
    for (dir, case) in &cases {
        for e in &case.expected {
            assert!(
                dir.join("repo").join(&e.file).exists(),
                "{}: expected file {} exists",
                case.name,
                e.file
            );
        }
    }

    // 匹配器：子串 ∪ 同族
    let cand = |file: &str, matcher: &str| Candidate {
        id: format!("{matcher}-x"),
        slug: String::new(),
        matcher_id: matcher.to_string(),
        channel: CandidateChannel::Rule,
        file: file.to_string(),
        line: 1,
        end_line: None,
        snippet: "x".to_string(),
        note: None,
        evidence_id: None,
    };
    let exp = vec![ExpectedFinding {
        file: "main.go".into(),
        category: "cmdi".into(),
        sink_symbol: None,
        severity: None,
        visible_to_rule: true,
    }];
    let m = score_candidates(&exp, &[cand("main.go", "cmdi-go-exec")]);
    assert_eq!(m.matched, 1, "cmdi ⊂ cmdi-go-exec 子串命中");
    let m = score_candidates(&exp, &[cand("other.go", "cmdi-go-exec")]);
    assert_eq!(m.matched, 0, "文件不匹配不计");
    let exp2 = vec![ExpectedFinding {
        file: "config.go".into(),
        category: "secrets-exposure".into(),
        sink_symbol: None,
        severity: None,
        visible_to_rule: true,
    }];
    let m = score_candidates(&exp2, &[cand("config.go", "floor-const-credential")]);
    assert_eq!(m.matched, 1, "secrets-exposure ≡ hardcoded 族互通");
}

#[test]
fn rule_invisible_expectations_leave_the_floor_denominator() {
    // 规则看不见的期望（跨文件授权语义）不能算进规则下限分母——否则门禁
    // 在拿规则去背它本来就看不见的题，长期只会得到假失败。
    use fiora_core::{Candidate, CandidateChannel};
    use fiora_eval::{score_candidates, ExpectedFinding};

    let cand = |file: &str, matcher: &str| Candidate {
        id: format!("{matcher}-x"),
        slug: String::new(),
        matcher_id: matcher.to_string(),
        channel: CandidateChannel::Rule,
        file: file.to_string(),
        line: 1,
        end_line: None,
        snippet: "x".to_string(),
        note: None,
        evidence_id: None,
    };
    let exp = vec![
        ExpectedFinding {
            file: "main.go".into(),
            category: "cmdi".into(),
            sink_symbol: None,
            severity: None,
            visible_to_rule: true,
        },
        ExpectedFinding {
            file: "handler.go".into(),
            category: "tenant-isolation-bypass".into(),
            sink_symbol: None,
            severity: None,
            visible_to_rule: false,
        },
    ];
    let m = score_candidates(&exp, &[cand("main.go", "cmdi-go-exec")]);
    assert_eq!(m.expected_total, 1, "分母只含规则可见期望");
    assert_eq!(m.matched, 1);
    assert_eq!(m.recall, 1.0);
    assert_eq!(m.invisible_total, 1);
    assert_eq!(m.invisible_matched, 0);
    assert!(
        m.precision.is_none(),
        "规则候选未判定，precision 必须是 n/a 而不是 1.0"
    );
    assert!(m.precision_basis.contains("n/a") || m.precision_basis.contains("未判定"));

    // 规则命中了标注为不可见的期望 = 语料标注错了，必须可被检测
    let mislabeled = vec![ExpectedFinding {
        file: "handler.go".into(),
        category: "idor".into(),
        sink_symbol: None,
        severity: None,
        visible_to_rule: false,
    }];
    let m = score_candidates(
        &mislabeled,
        &[cand("handler.go", "idor-request-id-no-check")],
    );
    assert_eq!(m.invisible_matched, 1);
    assert_eq!(m.expected_total, 0, "不可见期望不进规则分母");
}

#[test]
fn judged_precision_is_measured_and_candidate_precision_is_not() {
    // 聚合口径：只要案例里有一条走了判定通道，precision 就是测出来的；
    // 纯规则候选的聚合必须报 n/a。
    use fiora_core::{Candidate, CandidateChannel};
    use fiora_eval::{aggregate, score_candidates, ExpectedFinding};

    let judged = score(
        &[exp("a.go", "sqli", None)],
        &[finding("a.go", "sqli", "db.Exec", true)],
        1.0,
        10,
    );
    assert_eq!(judged.precision, Some(1.0));
    let total = aggregate(&[judged]);
    assert_eq!(total.precision, Some(1.0));

    let cand = Candidate {
        id: "c".into(),
        slug: String::new(),
        matcher_id: "cmdi-go-exec".into(),
        channel: CandidateChannel::Rule,
        file: "main.go".into(),
        line: 1,
        end_line: None,
        snippet: "x".into(),
        note: None,
        evidence_id: None,
    };
    let only_rules = aggregate(&[score_candidates(
        &[ExpectedFinding {
            file: "main.go".into(),
            category: "cmdi".into(),
            sink_symbol: None,
            severity: None,
            visible_to_rule: true,
        }],
        &[cand],
    )]);
    assert!(
        only_rules.precision.is_none(),
        "纯规则通道聚合 precision = n/a"
    );
}

#[test]
fn authorization_vocabulary_variants_match_same_ground_truth() {
    // 判定层写 missing-authorization / broken-access-control / idor，基准写其中
    // 任一种——不能因为词表选择把一个真阳性记成漏报。
    let expected = vec![
        ExpectedFinding {
            file: "routes/api.js".into(),
            category: "broken-access-control".into(),
            sink_symbol: Some("dumpSessions".into()),
            severity: None,
            visible_to_rule: true,
        },
        ExpectedFinding {
            file: "routes/api.js".into(),
            category: "missing-authorization".into(),
            sink_symbol: Some("listAuditLog".into()),
            severity: None,
            visible_to_rule: true,
        },
    ];
    for cat in ["missing-authorization", "broken-access-control", "idor"] {
        let m = score(
            &expected,
            &[finding("routes/api.js", cat, "dumpSessions", true)],
            0.0,
            0,
        );
        assert_eq!(m.matched, 1, "{cat} 应命中 broken-access-control 基准");
        let m = score(
            &expected,
            &[finding("routes/api.js", cat, "listAuditLog", true)],
            0.0,
            0,
        );
        assert_eq!(m.matched, 1, "{cat} 应命中 missing-authorization 基准");
    }
    // 授权面与鉴权面互通，但不能与注入面互通
    let inj = finding("routes/api.js", "sqli", "dumpSessions", true);
    assert_eq!(score(&expected, &[inj], 0.0, 0).matched, 0);

    // 多租户隔离与 IDOR 同属授权面：租户身份取自请求头，模型写 idor 也算命中
    let tenant_expected = ExpectedFinding {
        file: "handler.go".into(),
        category: "tenant-isolation-bypass".into(),
        sink_symbol: Some("store.OrdersByTenant".into()),
        severity: None,
        visible_to_rule: false,
    };
    let tenant_found = finding("handler.go", "idor", "store.OrdersByTenant", true);
    assert_eq!(
        score(
            std::slice::from_ref(&tenant_expected),
            &[tenant_found],
            0.0,
            0
        )
        .matched,
        1,
        "tenant-isolation-bypass 与 idor 必须互通"
    );

    // 类别词表完全不同、但同文件同 sink（身份锚点精确一致）→ 算命中：
    // 判定层把「未鉴权泄漏会话」写成 session-exposure，不该记成漏报
    let vocabulary = finding("routes/api.js", "session-exposure", "dumpSessions", true);
    assert_eq!(
        score(&expected, &[vocabulary], 0.0, 0).matched,
        1,
        "同文件 + sink 精确一致时应命中，类别只是词表选择"
    );
}

#[test]
fn evidence_sink_stands_in_for_a_missing_sink_symbol() {
    // 判定层没带 sink_symbol：回落到 evidence_ref 指向的证据骨架坐标再匹配。
    let mut f = finding("app.go", "cmdi", "", true);
    f.evidence_ref = Some("ev-1".into());
    let mut sinks = std::collections::HashMap::new();
    sinks.insert("ev-1".to_string(), "c.Run".to_string());
    let m = fiora_eval::score_with_evidence(
        &[exp("app.go", "cmdi", Some("c.Run"))],
        &[f],
        0.0,
        0,
        &sinks,
    );
    assert_eq!(
        (m.matched, m.expected_total),
        (1, 1),
        "空 sink 应回落到证据骨架"
    );

    // 没有证据坐标时同样的 finding 不命中：回落只对真实锚定的结论生效。
    let bare = finding("app.go", "cmdi", "", true);
    let m2 = fiora_eval::score_with_evidence(
        &[exp("app.go", "cmdi", Some("c.Run"))],
        &[bare],
        0.0,
        0,
        &std::collections::HashMap::new(),
    );
    assert_eq!(m2.matched, 0, "无证据坐标不得凭空命中");
}

#[test]
fn sink_identity_is_the_call_name_not_the_owner_spelling() {
    // 同一行同一个调用，语料写变量名、判定层写声明类型——不算漏报。
    let f = finding("app.go", "cmdi", "(*exec.Cmd).Run", true);
    assert!(
        matches(&f, &exp("app.go", "cmdi", Some("c.Run"))),
        "`c.Run` 与 `(*exec.Cmd).Run` 是同一处调用"
    );
    // 前缀仍要区分：不同调用名不得互相顶替。
    let f2 = finding("app.go", "sqli", "db.Raw", true);
    assert!(!matches(&f2, &exp("app.go", "sqli", Some("db.Exec"))));
    // 裸 token 仍走子串语义，不放宽成「任一同名调用」。
    let f3 = finding("app.go", "xss", "res.send", true);
    assert!(!matches(&f3, &exp("app.go", "xss", Some("write"))));
}
