use fiora_core::id::candidate_id;
use fiora_core::{CallHop, Candidate, CandidateChannel, EntryAnchor, EvidenceGrade, HopQuality};
use fiora_evidence::{
    is_complete, mark_dead_code, pre_assemble, three_elements, upgrade_with_chain,
};
use fiora_scanner::{EntryKind, SurfaceEntry};

fn cand(slug: &str, file: &str, line: u32, note: Option<String>) -> Candidate {
    Candidate {
        id: candidate_id(slug, file, line),
        slug: slug.to_string(),
        matcher_id: slug.to_string(),
        channel: CandidateChannel::Rule,
        file: file.to_string(),
        line,
        end_line: None,
        snippet: "db.Exec(fmt.Sprintf(...))".to_string(),
        note,
        evidence_id: None,
    }
}

fn entry(file: &str, line: u32, route: &str) -> SurfaceEntry {
    SurfaceEntry {
        file: file.to_string(),
        line,
        symbol: format!("GET {route}"),
        kind: EntryKind::Http,
        route: Some(route.to_string()),
    }
}

#[test]
fn pre_assemble_attaches_entries_and_taint_sources() {
    let c = cand(
        "sqli-sprintf",
        "api/query.go",
        42,
        Some(r#"dataflow: [{"content":[{"label":"user input"}],"location":{"path":"api/query.go","start":{"line":7}}}]"#.to_string()),
    );
    let surface = vec![entry("api/query.go", 8, "/users")];

    let map = pre_assemble(
        std::slice::from_ref(&c),
        &surface,
        std::path::Path::new("."),
    );
    let ev = map.get(&c.id).expect("evidence pre-assembled");

    assert_eq!(
        ev.grade,
        EvidenceGrade::DataflowVerified,
        "taint trace = engine-verified dataflow"
    );
    assert_eq!(ev.sources.len(), 1);
    assert_eq!(ev.sources[0].line, 7);
    assert_eq!(ev.entries.len(), 1);
    assert!(three_elements(ev).entry);
    assert!(is_complete(ev));
}

#[test]
fn pre_assemble_without_taint_stays_inferred_not_fake_verified() {
    let c = cand("missing-auth", "api/hidden.go", 3, None);
    let map = pre_assemble(std::slice::from_ref(&c), &[], std::path::Path::new("."));
    let ev = map.get(&c.id).unwrap();
    assert_eq!(ev.grade, EvidenceGrade::Inferred);
    assert!(
        !is_complete(ev),
        "no source, no entry — not complete, and honestly so"
    );
}

#[test]
fn upgrade_with_chain_promotes_grade_and_keeps_unresolved_visible() {
    let c = cand("sqli-sprintf", "api/query.go", 42, None);
    let surface = vec![entry("api/query.go", 8, "/users")];
    let mut map = pre_assemble(
        std::slice::from_ref(&c),
        &surface,
        std::path::Path::new("."),
    );
    let ev = map.get_mut(&c.id).unwrap();

    upgrade_with_chain(
        ev,
        vec![
            CallHop {
                from: "GET /users".into(),
                to: "handler".into(),
                quality: HopQuality::Traced,
            },
            CallHop {
                from: "handler".into(),
                to: "sqli-sprintf".into(),
                quality: HopQuality::Traced,
            },
        ],
        vec![EntryAnchor {
            symbol: "GET /users".into(),
            file: "api/query.go".into(),
            line: 8,
            route: Some("/users".into()),
        }],
    );
    assert_eq!(ev.grade, EvidenceGrade::CallchainVerified);
    assert!(ev.unresolved_hops.is_empty());

    // A hop through reflection is never laundered into "verified".
    let mut ev2 = pre_assemble(
        std::slice::from_ref(&c),
        &surface,
        std::path::Path::new("."),
    )
    .remove(&c.id)
    .unwrap();
    upgrade_with_chain(
        &mut ev2,
        vec![CallHop {
            from: "dispatch".into(),
            to: "sqli-sprintf".into(),
            quality: HopQuality::Unresolved,
        }],
        vec![],
    );
    assert_ne!(ev2.grade, EvidenceGrade::CallchainVerified);
    assert_eq!(ev2.unresolved_hops.len(), 1);
}

#[test]
fn dead_code_marking_is_explicit() {
    let c = cand("rce-exec", "pkg/legacy.go", 9, None);
    let mut map = pre_assemble(std::slice::from_ref(&c), &[], std::path::Path::new("."));
    let ev = map.get_mut(&c.id).unwrap();
    mark_dead_code(ev);
    assert_eq!(ev.grade, EvidenceGrade::DeadCode);
}
