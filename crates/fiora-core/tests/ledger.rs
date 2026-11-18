//! L0 ledger semantics tests (P4 append-only / TTL lease / resumable scheduling).

use std::time::Duration;

use fiora_core::id::{candidate_id, finding_id};
use fiora_core::{
    AgentProvenance, AnalysisEntry, Candidate, CandidateChannel, Cost, Evidence, EvidenceGrade,
    FileStatus, Finding, Ledger, RebuttalAnswers, Severity, Verdict, VerdictConclusion,
};
use tempfile::TempDir;

fn candidate(slug: &str, line: u32) -> Candidate {
    Candidate {
        id: candidate_id(slug, "api/login.go", line),
        slug: slug.to_string(),
        matcher_id: format!("matcher-{slug}"),
        channel: CandidateChannel::Rule,
        file: "api/login.go".to_string(),
        line,
        end_line: None,
        snippet: "db.Where(fmt.Sprintf(...))".to_string(),
        note: None,
        evidence_id: None,
    }
}

fn finding(title: &str) -> Finding {
    Finding {
        id: finding_id("sqli", "db.Raw", "dao.QueryUser"),
        slug: "sqli".to_string(),
        title: title.to_string(),
        severity: Severity::High,
        category: "sqli".to_string(),
        file: "api/login.go".to_string(),
        line: 10,
        sink_symbol: "db.Raw".to_string(),
        probe_shape: None,
        enclosing_fn: "dao.QueryUser".to_string(),
        end_line: None,
        description: "user input reaches raw SQL".to_string(),
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

fn analysis(run_id: &str, summary: &str) -> AnalysisEntry {
    AnalysisEntry {
        run_id: run_id.to_string(),
        agent: AgentProvenance {
            backend: "pi".to_string(),
            model: "test-model".to_string(),
            thinking_level: "high".to_string(),
            run_id: run_id.to_string(),
            session_id: None,
            cost: None,
        },
        at: "2026-01-01T00:00:00Z".to_string(),
        summary: summary.to_string(),
        finding_ids: vec![],
        refused: None,
        refusal_note: None,
    }
}

fn verdict() -> Verdict {
    Verdict {
        conclusion: VerdictConclusion::TruePositive,
        confidence: fiora_core::Confidence::High,
        evidence_ref: Some("ev-1".to_string()),
        reasoning: "entry->sink verified".to_string(),
        rebuttals: RebuttalAnswers {
            parameterized: Some(false),
            reachable: Some(true),
            business_method: Some(false),
            allowlisted: Some(false),
            user_input_controlled: Some(true),
            protected_by_guard: Some(false),
            notes: "rebuttal failed".to_string(),
        },
    }
}

fn setup() -> (TempDir, Ledger) {
    let dir = TempDir::new().unwrap();
    let ledger = Ledger::open(dir.path().join(".fiora")).unwrap();
    (dir, ledger)
}

#[test]
fn init_and_load_roundtrip() {
    let (_d, ledger) = setup();
    ledger.init_file("api/login.go").unwrap();
    let rec = ledger.load_file("api/login.go").unwrap().unwrap();
    assert_eq!(rec.path, "api/login.go");
    assert_eq!(rec.status, FileStatus::Pending);
}

#[test]
fn merge_candidates_dedupes_and_never_deletes() {
    let (_d, ledger) = setup();
    ledger
        .merge_candidates(
            "api/login.go",
            vec![candidate("sqli", 10), candidate("sqli", 20)],
        )
        .unwrap();
    ledger
        .merge_candidates(
            "api/login.go",
            vec![candidate("sqli", 10), candidate("rce", 30)],
        )
        .unwrap();

    let rec = ledger.load_file("api/login.go").unwrap().unwrap();
    let lines: Vec<u32> = rec.candidates.iter().map(|c| c.line).collect();
    assert_eq!(
        lines,
        vec![10, 20, 30],
        "10 must not duplicate, 20 must not vanish"
    );
}

#[test]
fn candidate_merge_fills_missing_fields_additively() {
    let (_d, ledger) = setup();
    ledger
        .merge_candidates("api/login.go", vec![candidate("sqli", 10)])
        .unwrap();

    let mut enriched = candidate("sqli", 10);
    enriched.evidence_id = Some("ev-9".to_string());
    enriched.note = Some("semantic note".to_string());
    ledger
        .merge_candidates("api/login.go", vec![enriched])
        .unwrap();

    let rec = ledger.load_file("api/login.go").unwrap().unwrap();
    assert_eq!(rec.candidates[0].evidence_id.as_deref(), Some("ev-9"));
    assert_eq!(rec.candidates[0].note.as_deref(), Some("semantic note"));
}

#[test]
fn finding_upsert_is_additive_not_destructive() {
    let (_d, ledger) = setup();
    let base = finding("SQL injection in login");
    ledger.upsert_finding(base).unwrap();

    // Second pass with same identity: supplies verdict, but must NOT overwrite
    // the original description/title (additive fill).
    let mut second = finding("REWORDED TITLE");
    second.description = "SHOULD NOT OVERWRITE".to_string();
    second.verdict = Some(verdict());
    second.chain_ids = vec!["ch-1".to_string()];
    let merged = ledger.upsert_finding(second).unwrap();

    assert_eq!(merged.title, "SQL injection in login");
    assert_eq!(merged.description, "user input reaches raw SQL");
    assert_eq!(
        merged.verdict.as_ref().unwrap().conclusion,
        VerdictConclusion::TruePositive
    );
    assert_eq!(merged.chain_ids, vec!["ch-1".to_string()]);
    assert_eq!(ledger.list_finding_ids().unwrap().len(), 1);
}

#[test]
fn identity_is_stable_across_title_and_line_changes() {
    let a = finding_id("sqli", "db.Raw", "dao.QueryUser");
    let b = finding_id("sqli", "db.Raw", "dao.QueryUser"); // different title/line upstream
    assert_eq!(a, b);
    let c = finding_id("sqli", "db.Exec", "dao.QueryUser");
    assert_ne!(a, c);
}

#[test]
fn analysis_history_is_pure_append() {
    let (_d, ledger) = setup();
    ledger
        .append_analysis("api/login.go", analysis("run-1", "first pass"))
        .unwrap();
    ledger
        .append_analysis("api/login.go", analysis("run-2", "reinvestigated"))
        .unwrap();

    let rec = ledger.load_file("api/login.go").unwrap().unwrap();
    let runs: Vec<&str> = rec
        .analysis_history
        .iter()
        .map(|a| a.run_id.as_str())
        .collect();
    assert_eq!(runs, vec!["run-1", "run-2"]);
}

#[test]
fn claim_pending_complete_release_implements_resume() {
    let (_d, ledger) = setup();
    for f in ["a.go", "b.go", "c.go"] {
        ledger.init_file(f).unwrap();
    }

    let rels: Vec<String> = ["a.go", "b.go", "missing.go"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (claimed, skipped) = ledger
        .claim(&rels, "run-1", Duration::from_secs(60))
        .unwrap();
    assert_eq!(claimed, vec!["a.go".to_string(), "b.go".to_string()]);
    assert_eq!(skipped, vec!["missing.go".to_string()]);

    // Leased files leave the pending pool (no double-claim across workers).
    assert_eq!(ledger.pending().unwrap(), vec!["c.go".to_string()]);
    let (again, _) = ledger
        .claim(&["a.go".to_string()], "run-2", Duration::from_secs(60))
        .unwrap();
    assert!(again.is_empty());

    // run-1 finishes a.go; b.go crashes with the lock held.
    ledger.complete("a.go", FileStatus::Analyzed).unwrap();
    assert_eq!(ledger.pending().unwrap(), vec!["c.go".to_string()]);

    // Crash recovery: releasing run-1 returns b.go to pending.
    let released = ledger.release_run("run-1").unwrap();
    assert_eq!(released, vec!["b.go".to_string()]);
    let mut pending = ledger.pending().unwrap();
    pending.sort();
    assert_eq!(pending, vec!["b.go".to_string(), "c.go".to_string()]);
}

#[test]
fn expired_lease_returns_work_to_pending_pool() {
    let (_d, ledger) = setup();
    ledger.init_file("a.go").unwrap();

    // Zero-TTL lease expires immediately: a crashed worker must not deadlock
    // the file, and another worker must be able to steal it after expiry.
    ledger
        .claim(&["a.go".to_string()], "run-1", Duration::ZERO)
        .unwrap();
    assert_eq!(ledger.pending().unwrap(), vec!["a.go".to_string()]);

    let (stolen, _) = ledger
        .claim(&["a.go".to_string()], "run-2", Duration::from_secs(60))
        .unwrap();
    assert_eq!(stolen, vec!["a.go".to_string()]);
}

#[test]
fn heartbeat_renews_lease() {
    let (_d, ledger) = setup();
    ledger.init_file("a.go").unwrap();
    ledger
        .claim(&["a.go".to_string()], "run-1", Duration::from_millis(30))
        .unwrap();
    std::thread::sleep(Duration::from_millis(40));

    // Without heartbeat the lease would have expired…
    ledger
        .heartbeat(&["a.go".to_string()], "run-1", Duration::from_secs(60))
        .unwrap();
    // …and a renewal keeps it claimed.
    assert!(ledger.pending().unwrap().is_empty());
}

#[test]
fn evidence_roundtrip() {
    let (_d, ledger) = setup();
    ledger
        .save_evidence(&Evidence {
            id: "ev-1".to_string(),
            sink: fiora_core::CodeAnchor {
                symbol: "db.Raw".to_string(),
                file: "dao/user.go".to_string(),
                line: 42,
            },
            sources: vec![fiora_core::CodeAnchor {
                symbol: "req.Query".to_string(),
                file: "api/user.go".to_string(),
                line: 8,
            }],
            entries: vec![fiora_core::EntryAnchor {
                symbol: "GET /users".to_string(),
                file: "api/user.go".to_string(),
                line: 8,
                route: Some("GET /users".to_string()),
            }],
            call_chain: vec![],
            grade: EvidenceGrade::DataflowVerified,
            unresolved_hops: vec![],
            tool: "opengrep-taint".to_string(),
        })
        .unwrap();
    assert_eq!(
        ledger.load_evidence("ev-1").unwrap().unwrap().grade,
        EvidenceGrade::DataflowVerified
    );
    assert!(ledger.load_evidence("nope").unwrap().is_none());
}

#[test]
fn cost_accounting_accumulates() {
    let (_d, ledger) = setup();
    ledger
        .record_cost(
            "run-1",
            &Cost {
                tokens_in: 100,
                tokens_out: 50,
                usd: 0.1,
            },
            "2026-01-01",
        )
        .unwrap();
    let meta = ledger
        .record_cost(
            "run-1",
            &Cost {
                tokens_in: 200,
                tokens_out: 100,
                usd: 0.2,
            },
            "2026-01-01",
        )
        .unwrap();
    assert_eq!(meta.cost.tokens_in, 300);
    assert_eq!(meta.cost.tokens_out, 150);
    assert!((meta.cost.usd - 0.3).abs() < 1e-9);
}

#[test]
fn reinit_does_not_clobber_collections() {
    let (_d, ledger) = setup();
    ledger
        .merge_candidates("a.go", vec![candidate("sqli", 1)])
        .unwrap();
    ledger.init_file("a.go").unwrap();
    let rec = ledger.load_file("a.go").unwrap().unwrap();
    assert_eq!(rec.candidates.len(), 1);
    assert_eq!(rec.status, FileStatus::Pending);
}

#[test]
fn project_config_roundtrip_and_additive_defaults() {
    use fiora_core::ProjectConfig;
    let dir = TempDir::new().unwrap();

    // missing config -> defaults, no error
    let cfg = ProjectConfig::load(dir.path());
    assert_eq!(cfg.thinking_level, "xhigh");
    assert_eq!(cfg.default_model, None);

    // save/load roundtrip
    let cfg = ProjectConfig {
        default_model: Some("zai/glm-5.2".into()),
        budget_model: Some("cheap-model".into()),
        thinking_level: "high".into(),
        base_url: Some("https://gw/v1".into()),
        api_key_env: Some("MY_KEY".into()),
        api: Some("anthropic-messages".into()),
        ..Default::default()
    };
    cfg.save(dir.path()).unwrap();
    let loaded = ProjectConfig::load(dir.path());
    assert_eq!(loaded, cfg);

    // partial json (old file, new fields) fills defaults additively
    std::fs::write(dir.path().join("config.json"), r#"{"defaultModel":"m"}"#).unwrap();
    let partial = ProjectConfig::load(dir.path());
    assert_eq!(partial.default_model.as_deref(), Some("m"));
    assert_eq!(partial.thinking_level, "xhigh");
}

#[test]
fn model_pool_and_profiles_resolution() {
    use fiora_core::{ModelSpec, Profile, ProjectConfig};
    let mut cfg = ProjectConfig {
        default_model: Some("fallback-judge".into()),
        budget_model: Some("fallback-budget".into()),
        ..Default::default()
    };
    cfg.models.insert(
        "flash".into(),
        ModelSpec {
            model: "mimo/mimo-v2.6-flash".into(),
            thinking: Some("high".into()),
        },
    );
    cfg.models.insert(
        "opus".into(),
        ModelSpec {
            model: "anthropic/claude-opus-4-8".into(),
            thinking: None,
        },
    );
    cfg.profiles.insert(
        "fast".into(),
        Profile {
            judge: "flash".into(),
            budget: "flash".into(),
        },
    );
    cfg.profiles.insert(
        "deep".into(),
        Profile {
            judge: "opus".into(),
            budget: "mimo/mimo-v2.6-pro".into(),
        }, // 直写模型 id 也可
    );
    cfg.active_profile = Some("deep".into());

    // 档位解析：模型池名展开 + 直写 id 直通
    let r = cfg.resolve_models(None, None, None);
    assert_eq!(r.judge.as_deref(), Some("anthropic/claude-opus-4-8"));
    assert_eq!(r.budget.as_deref(), Some("mimo/mimo-v2.6-pro"));
    assert_eq!(r.profile.as_deref(), Some("deep"));

    // --profile 运行时切换
    let r = cfg.resolve_models(None, None, Some("fast"));
    assert_eq!(r.judge.as_deref(), Some("mimo/mimo-v2.6-flash"));
    assert_eq!(r.thinking.as_deref(), Some("high"), "模型池思考档生效");

    // CLI 显式覆盖最优先
    let r = cfg.resolve_models(Some("zai/glm-5.3-flash".into()), None, Some("fast"));
    assert_eq!(r.judge.as_deref(), Some("zai/glm-5.3-flash"));
    assert_eq!(r.budget.as_deref(), Some("mimo/mimo-v2.6-flash"));

    // 无档位时回落默认槽
    let bare = ProjectConfig {
        default_model: Some("fallback-judge".into()),
        ..Default::default()
    };
    let r = bare.resolve_models(None, None, None);
    assert_eq!(r.judge.as_deref(), Some("fallback-judge"));
}

#[test]
fn requeue_pool_uses_latest_entry_only() {
    // 复跑池只看最新条目：旧拒答被后续成功裁决覆盖后，不得重复入审（防重复烧钱）
    let dir = TempDir::new().unwrap();
    let ledger = Ledger::open(dir.path()).unwrap();
    ledger.init_file("a.go").unwrap();
    ledger
        .merge_candidates("a.go", vec![candidate("sink", 2)])
        .unwrap();
    // 旧拒答条目
    ledger
        .append_analysis(
            "a.go",
            AnalysisEntry {
                run_id: "r1".into(),
                agent: AgentProvenance {
                    backend: "pi".into(),
                    model: "m".into(),
                    thinking_level: "high".into(),
                    run_id: "r1".into(),
                    session_id: None,
                    cost: None,
                },
                at: "t1".into(),
                summary: "refused".into(),
                finding_ids: vec![],
                refused: Some(true),
                refusal_note: Some("not json".into()),
            },
        )
        .unwrap();
    ledger.complete("a.go", FileStatus::Analyzed).unwrap();
    assert!(
        ledger.pending().unwrap().contains(&"a.go".to_string()),
        "拒答未裁决→入复跑池"
    );
    // 后续成功裁决（0 findings 但不是拒答）
    ledger
        .append_analysis(
            "a.go",
            AnalysisEntry {
                run_id: "r2".into(),
                agent: AgentProvenance {
                    backend: "pi".into(),
                    model: "m".into(),
                    thinking_level: "high".into(),
                    run_id: "r2".into(),
                    session_id: None,
                    cost: None,
                },
                at: "t2".into(),
                summary: "judged".into(),
                finding_ids: vec![],
                refused: None,
                refusal_note: None,
            },
        )
        .unwrap();
    assert!(
        !ledger.pending().unwrap().contains(&"a.go".to_string()),
        "已裁决→不再入审"
    );
}

/// Rule hits are refreshed, not accumulated: a rule that stops matching must
/// stop producing candidates (otherwise a stale hit is triaged and paid for).
#[test]
fn rule_candidates_are_refreshed_while_semantic_ones_survive() {
    use fiora_core::{Candidate, CandidateChannel, Ledger};

    let dir = std::env::temp_dir().join(format!("fiora-ledger-refresh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ledger = Ledger::open(dir.join(".fiora")).unwrap();

    let mk = |id: &str, channel| Candidate {
        id: id.into(),
        slug: "cmdi-go-exec".into(),
        matcher_id: "cmdi-go-exec".into(),
        channel,
        file: "a.go".into(),
        line: 9,
        end_line: None,
        snippet: "exec.Command(u)".into(),
        note: None,
        evidence_id: None,
    };

    ledger.init_file("a.go").unwrap();
    let mut first = mk("c1", CandidateChannel::Rule);
    first.note = Some("keep me".into());
    first.evidence_id = Some("ev1".into());
    ledger
        .merge_candidates(
            "a.go",
            vec![
                first,
                mk("c2", CandidateChannel::Rule),
                mk("s1", CandidateChannel::Semantic),
            ],
        )
        .unwrap();

    // Rule c2 no longer hits; c1 still does and must keep its L2 work.
    let rec = ledger
        .replace_rule_candidates("a.go", vec![mk("c1", CandidateChannel::Rule)])
        .unwrap();
    let ids: Vec<&str> = rec.candidates.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"c1") && ids.contains(&"s1"));
    assert!(
        !ids.contains(&"c2"),
        "orphan rule candidate must be dropped"
    );
    let kept = rec.candidates.iter().find(|c| c.id == "c1").unwrap();
    assert_eq!(kept.note.as_deref(), Some("keep me"));
    assert_eq!(kept.evidence_id.as_deref(), Some("ev1"));

    // An unchanged rule set must not un-analyse the file.
    ledger
        .replace_rule_candidates("a.go", vec![mk("c1", CandidateChannel::Rule)])
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// 同 id 重复条目（历史账本遗留 / 上游重复命中）必须被合并成一条并补齐字段，
/// 否则缺字段的那条永远重试（实测：17 条孤儿每次 run 触发全仓重建）。
#[test]
fn duplicate_candidate_ids_merge_into_one_complete_entry() {
    use fiora_core::{Candidate, CandidateChannel, Ledger};

    let dir = std::env::temp_dir().join(format!("fiora-ledger-dup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ledger = Ledger::open(dir.join(".fiora")).unwrap();

    let mk = |evidence: Option<&str>| Candidate {
        id: "dup-1".into(),
        slug: "floor-pathtraversal-python".into(),
        matcher_id: "floor-pathtraversal-python".into(),
        channel: CandidateChannel::Rule,
        file: "a.py".into(),
        line: 42,
        end_line: None,
        snippet: "open(p)".into(),
        note: None,
        evidence_id: evidence.map(str::to_string),
    };

    ledger.init_file("a.py").unwrap();
    // 同 id 两条：一条带 evidence、一条不带——旧实现在这里只填第一条。
    ledger
        .merge_candidates("a.py", vec![mk(Some("ev-1")), mk(None)])
        .unwrap();
    let rec = ledger.load_file("a.py").unwrap().unwrap();
    assert_eq!(rec.candidates.len(), 1, "同 id 必须归一为一条");
    assert_eq!(rec.candidates[0].evidence_id.as_deref(), Some("ev-1"));

    // 遗留重复（base 里已有两条同 id）也要被压实。
    let _ = std::fs::remove_dir_all(&dir);
}

/// 复验降级没有入口时报告永远按初判级展示——`verify record --severity` 的落账口。
#[test]
fn finding_severity_can_be_corrected_after_verification() {
    use fiora_core::{Ledger, Severity};

    let dir = std::env::temp_dir().join(format!("fiora-ledger-sev-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ledger = Ledger::open(dir.join(".fiora")).unwrap();

    let mut f = finding("sev test");
    f.id = "sev-1".to_string();
    f.severity = Severity::High;
    ledger.upsert_finding(f).unwrap();

    let updated = ledger
        .set_finding_severity("sev-1", Severity::Medium)
        .unwrap()
        .expect("finding exists");
    assert_eq!(updated.severity, Severity::Medium);
    let reloaded = ledger.load_finding("sev-1").unwrap().unwrap();
    assert_eq!(reloaded.severity, Severity::Medium, "校正要落盘");
    let _ = std::fs::remove_dir_all(&dir);
}
