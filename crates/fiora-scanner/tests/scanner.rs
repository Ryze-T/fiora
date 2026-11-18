//! L1 scanner tests: rule corpus loading, normalization, tech detection,
//! surface enumeration.

use std::fs;

use fiora_scanner::normalize::{normalize, parse_json};
use fiora_scanner::rules::{RuleRegistry, RuleSource};
use fiora_scanner::surface::enumerate;
use fiora_scanner::tech::detect;
use tempfile::TempDir;

#[test]
fn builtin_corpus_loads_and_validates() {
    let reg = RuleRegistry::load(None, None).unwrap();
    assert!(
        reg.len() >= 20,
        "vuln-mining four classes ported, got {}",
        reg.len()
    );
    assert!(reg.get("sqli-sprintf-into-where").is_some());
    let rule = reg.get("sqli-sprintf-into-where").unwrap();
    assert_eq!(rule.source, RuleSource::Builtin);
    assert!(rule.spec.languages.contains(&"go".to_string()));
}

#[test]
fn project_rules_override_builtin_by_id() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("override.yaml"),
        r#"
rules:
  - id: sqli-sprintf-into-where
    languages: [go]
    severity: INFO
    message: "narrowed by the team: only Where(fmt.Sprintf) with user input"
"#,
    )
    .unwrap();

    let reg = RuleRegistry::load(None, Some(dir.path())).unwrap();
    let rule = reg.get("sqli-sprintf-into-where").unwrap();
    assert_eq!(
        rule.source,
        RuleSource::Project,
        "project level must override builtin"
    );
    assert_eq!(rule.spec.severity, "INFO");
    let builtin_only = RuleRegistry::load(None, None).unwrap();
    assert_eq!(
        reg.len(),
        builtin_only.len(),
        "override replaces, does not duplicate"
    );
}

#[test]
fn invalid_rules_are_rejected_before_running() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("bad.yaml"),
        r#"
rules:
  - id: ""
    languages: [go]
"#,
    )
    .unwrap();
    assert!(RuleRegistry::load(None, Some(dir.path())).is_err());
}

#[test]
fn normalize_produces_stable_ids_and_slugs() {
    let json = r#"{
      "results": [
        {
          "check_id": "rules/sqli.yaml.sqli-sprintf-into-where",
          "path": "api/login.go",
          "start": {"line": 10, "col": 2},
          "end": {"line": 12, "col": 5},
          "extra": {
            "message": "SQL注入候选",
            "severity": "ERROR",
            "lines": "db.Where(fmt.Sprintf(\"%s\", q))"
          }
        },
        {
          "check_id": "rules/sqli.yaml.sqli-sprintf-into-where",
          "path": "api/login.go",
          "start": {"line": 10, "col": 2},
          "extra": {"message": "dup", "severity": "ERROR", "lines": "dup"}
        }
      ],
      "errors": []
    }"#;
    let report = parse_json(json).unwrap();
    let cands = normalize(&report, ".");
    // 同规则同位置的重复命中（pattern 多分支）在源头就归一成一条：此前把两条
    // 同 id 候选交给账本，而合并只填第一条，第二条永远缺 evidence、每次重试。
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].slug, "sqli-sprintf-into-where");
    assert_eq!(cands[0].file, "api/login.go");
    assert_eq!(cands[0].line, 10);
    assert_eq!(cands[0].end_line, Some(12));
}

#[test]
fn tech_detection_maps_sentinels_to_tags() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("go.mod"),
        "require github.com/gin-gonic/gin v1.9.0\n",
    )
    .unwrap();
    fs::write(dir.path().join("requirements.txt"), "django==5.0\n").unwrap();

    let report = detect(dir.path());
    for tag in ["nextjs", "react", "node", "go", "gin", "python", "django"] {
        assert!(
            report.tags.contains(&tag.to_string()),
            "missing tag {tag}: {:?}",
            report.tags
        );
    }
}

#[test]
fn surface_enumeration_finds_http_entries() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("api")).unwrap();
    fs::write(
        root.join("api/routes.go"),
        r#"
package api

func Setup(r *gin.Engine) {
	r.GET("/users/:id", GetUser)
	r.POST("/login", Login)
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("api/server.py"),
        r#"
@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {}
"#,
    )
    .unwrap();
    // Next.js file-based routing
    fs::create_dir_all(root.join("app/dashboard")).unwrap();
    fs::write(
        root.join("app/dashboard/page.tsx"),
        "export default function Page(){}",
    )
    .unwrap();

    let entries = enumerate(root);
    let routes: Vec<_> = entries.iter().filter_map(|e| e.route.clone()).collect();
    assert!(
        routes.contains(&"/users/:id".to_string()),
        "gin route missing: {routes:?}"
    );
    assert!(
        routes.contains(&"/login".to_string()),
        "gin POST missing: {routes:?}"
    );
    assert!(
        routes.contains(&"/items/{item_id}".to_string()),
        "fastapi route missing: {routes:?}"
    );
    assert!(
        routes.contains(&"/dashboard".to_string()),
        "next file route missing: {routes:?}"
    );
}
