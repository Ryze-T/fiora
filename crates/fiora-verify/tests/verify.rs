//! L4 tests: pre/post-patch differential repro + fix verification over a real
//! git repository fixture (two commits: vulnerable -> patched).

use std::fs;
use std::path::Path;
use std::process::Command;

use fiora_core::{Confidence, Finding, RebuttalAnswers, Severity, Verdict, VerdictConclusion};
use fiora_verify::{
    diff_finding, probe_content, probe_worktree, to_verification, verify_fix, DiffVerdict,
    VulnerableState,
};
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) {
    let st = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

fn finding() -> Finding {
    Finding {
        id: "f1".into(),
        slug: "sqli".into(),
        title: "SQL injection".into(),
        severity: Severity::High,
        category: "sqli".into(),
        file: "api/vuln.go".into(),
        line: 3,
        end_line: None,
        sink_symbol: "db.Exec".into(),
        probe_shape: Some("db.Exec(fmt.Sprintf".into()),
        enclosing_fn: "QueryUser".into(),
        description: "sprintf into db.Exec".into(),
        impact: None,
        preconditions: vec![],
        data_flow: Some("req -> q -> db.Exec".into()),
        evidence_ref: None,
        repro_pack: None,
        verdict: Some(Verdict {
            conclusion: VerdictConclusion::TruePositive,
            confidence: Confidence::High,
            evidence_ref: None,
            reasoning: "r".into(),
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

/// Two-commit repo: vulnerable code first, then the fix.
fn repo_with_patch() -> (TempDir, String, String) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("api")).unwrap();
    git(root, &["init", "-q"]);
    fs::write(
        root.join("api/vuln.go"),
        "package api\n\nfunc QueryUser(db *DB, q string) {\n\tdb.Exec(fmt.Sprintf(\"...%s\", q))\n}\n",
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "vulnerable"]);
    let pre = rev(root);

    fs::write(
        root.join("api/vuln.go"),
        "package api\n\nfunc QueryUser(db *DB, q string) {\n\tdb.Exec(\"...\", q) // parameterized\n}\n",
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "fix"]);
    let post = rev(root);
    (dir, pre, post)
}

fn rev(root: &Path) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn differential_repro_confirms_fix_across_revisions() {
    let (dir, pre, post) = repo_with_patch();
    let d = diff_finding(dir.path(), &finding(), &pre, &post);
    assert_eq!(
        d.verdict,
        DiffVerdict::Fixed,
        "present pre, absent post => verified fix"
    );
    assert_eq!(d.pre.state, VulnerableState::Present);
    assert_eq!(d.post.state, VulnerableState::Absent);

    // and the reverse direction proves the vulnerability existed before the patch
    let rev_d = diff_finding(dir.path(), &finding(), &post, &pre);
    assert_eq!(rev_d.verdict, DiffVerdict::Regressed);
}

#[test]
fn differential_flags_persisting_vulnerabilities() {
    let (dir, pre, _post) = repo_with_patch();
    // pre vs pre: the vulnerable shape is on both sides
    let d = diff_finding(dir.path(), &finding(), &pre, &pre);
    assert_eq!(
        d.verdict,
        DiffVerdict::Persisting,
        "iron evidence that a patch did NOT fix it"
    );
}

#[test]
fn fix_verification_on_worktree() {
    let (dir, _pre, _post) = repo_with_patch();
    // working tree has the fix applied
    let d = verify_fix(dir.path(), &finding());
    assert_eq!(d.verdict, DiffVerdict::Fixed);

    // reintroduce the vulnerable shape -> persisting
    fs::write(
        dir.path().join("api/vuln.go"),
        "package api\n\ndb.Exec(fmt.Sprintf(q))\n",
    )
    .unwrap();
    let d2 = verify_fix(dir.path(), &finding());
    assert_eq!(d2.verdict, DiffVerdict::Persisting);
}

#[test]
fn probe_never_guesses() {
    // no file -> unknown (not "fixed" — honesty over convenience)
    let p = probe_content(&finding(), None);
    assert_eq!(p.state, VulnerableState::Unknown);

    // symbol missing entirely -> absent
    let p2 = probe_content(&finding(), Some("package api\nfunc Other() {}\n"));
    assert_eq!(p2.state, VulnerableState::Absent);

    // line drift: symbol present far from the recorded line -> still present
    let drifted =
        format!("package api\n{}\n", "x := 1\n".repeat(100)) + "db.Exec(fmt.Sprintf(q))\n";
    let p3 = probe_content(&finding(), Some(&drifted));
    assert_eq!(p3.state, VulnerableState::Present);
    assert!(p3.detail.contains("drifted"));

    // missing worktree file -> absent with explanation
    let tmp = TempDir::new().unwrap();
    let p4 = probe_worktree(tmp.path(), &finding());
    assert_eq!(p4.state, VulnerableState::Absent);
}

#[test]
fn verification_record_maps_verdicts() {
    let (dir, pre, post) = repo_with_patch();
    let d = diff_finding(dir.path(), &finding(), &pre, &post);
    let v = to_verification(&d, "static-diff", "2026-01-01T00:00:00Z");
    assert_eq!(v.verdict, "fixed");
    assert_eq!(v.method, "static-diff");
    assert!(v.notes.contains("pre:"));
}

/// 两个验证通道必须物理分离：差分结论只进 diffs/，绝不覆盖 finding 的
/// 实测记录（工作台实测事故：verify diff 把 4 条 live-prove 全冲成 fix-check）。
#[test]
fn diff_state_lands_in_diffs_dir_and_never_touches_finding_records() {
    let dir = tempfile::tempdir().unwrap();
    let v = fiora_core::Verification {
        method: "fix-check".into(),
        pre_state: "unknown".into(),
        post_state: "present".into(),
        verdict: "persisting".into(),
        at: "2026-01-01T00:00:00Z".into(),
        notes: "shape still present".into(),
    };
    let path = fiora_verify::record_diff_state(dir.path(), "abc123", &v).unwrap();
    assert_eq!(path, dir.path().join("diffs/abc123.json"));
    let got: fiora_core::Verification =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got.verdict, "persisting");
    // finding 账本目录根本不该出现
    assert!(!dir.path().join("findings").exists());
}
