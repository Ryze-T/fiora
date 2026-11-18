//! Surface inventory — trust-boundary entry enumeration (DESIGN.md §3).
//!
//! The coverage denominator (P: "coverage is counted from a ledger, not a call
//! graph"). Entries are a finite, syntactically enumerable set: file-based
//! routing is enumerated from the filesystem; code-based routing from route
//! declaration patterns. Every entry lands in the ledger with a review status —
//! "not reviewed" is an explicit row, never blank.

use std::fs;
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Http,
    Rpc,
    Queue,
    Cron,
    Cli,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceEntry {
    pub file: String,
    pub line: u32,
    pub symbol: String,
    pub kind: EntryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

const SRC_EXTS: &[&str] = &["go", "py", "ts", "tsx", "js", "jsx", "java", "kt"];

struct Pattern {
    regex: Regex,
    kind: EntryKind,
    /// capture group holding the route, if any
    route_group: Option<usize>,
}

fn patterns() -> Vec<Pattern> {
    let mk = |re: &str, kind: EntryKind, route_group: Option<usize>| Pattern {
        regex: Regex::new(re).unwrap(),
        kind,
        route_group,
    };
    vec![
        // Go frameworks (gin/echo/fiber/chi/gorilla style)
        mk(
            r#"(?m)^\s*(?:[\w.]+)\.(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Handle|HandleFunc|Any|Group)\(\s*"([^"]+)""#,
            EntryKind::Http,
            Some(1),
        ),
        // Express / Koa style
        mk(
            r#"(?m)^\s*(?:app|router|server)\.(?:get|post|put|patch|delete|all|use)\(\s*['"]([^'"]+)['"]"#,
            EntryKind::Http,
            Some(1),
        ),
        // Python FastAPI / Flask / Starlette decorators
        mk(
            r#"(?m)^\s*@(?:app|bp|api|router|blueprint)\.(?:get|post|put|patch|delete|route|websocket)\(\s*['"]([^'"]+)['"]"#,
            EntryKind::Http,
            Some(1),
        ),
        // Django urls
        mk(
            r#"(?m)^\s*(?:path|re_path|url)\(\s*['"]([^'"]+)['"]"#,
            EntryKind::Http,
            Some(1),
        ),
        // Spring / JAX-RS annotations
        mk(
            r#"@(?:Get|Post|Put|Patch|Delete|Request)Mapping"#,
            EntryKind::Http,
            None,
        ),
        mk(r#"@(?:Path|GET|POST|PUT|DELETE)\b"#, EntryKind::Http, None),
        // Next.js file-based routing handled separately below.
        // Queue consumers / RPC style markers
        mk(
            r#"(?m)^\s*func\s+\w*(?:Consumer|Handler|Consume)\w*\("#,
            EntryKind::Queue,
            None,
        ),
        mk(
            r#"(?m)^\s*def\s+\w*(?:consumer|handler|task)\w*\("#,
            EntryKind::Queue,
            None,
        ),
        // Cron / scheduled
        mk(
            r#"@(?:Scheduled|Cron)|cron\.(?:NewFunc|Start)|schedule\.\w+\("#,
            EntryKind::Cron,
            None,
        ),
    ]
}

/// Enumerate all trust-boundary entries under `root`.
pub fn enumerate(root: &Path) -> Vec<SurfaceEntry> {
    let mut out = Vec::new();
    let pats = patterns();
    let files = fiora_core::fsutil::list_files(root, SRC_EXTS).unwrap_or_default();
    for (rel, path) in files {
        scan_file(&rel, &path, &pats, &mut out);
    }
    out.sort_by_key(|a| (a.file.clone(), a.line));
    out
}

fn scan_file(rel: &str, path: &Path, pats: &[Pattern], out: &mut Vec<SurfaceEntry>) {
    // File-based routing (Next.js App/Pages router) — filesystem = route table.
    if rel.starts_with("app/") || rel.starts_with("src/app/") || rel.starts_with("pages/") {
        if let Some(entry) = file_route_entry(rel) {
            out.push(entry);
        }
    }

    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for (idx, line) in content.lines().enumerate() {
        for p in pats {
            if let Some(caps) = p.regex.captures(line) {
                let route = p
                    .route_group
                    .and_then(|g| caps.get(g))
                    .map(|m| m.as_str().to_string());
                out.push(SurfaceEntry {
                    file: rel.to_string(),
                    line: (idx + 1) as u32,
                    symbol: line.trim().chars().take(120).collect(),
                    kind: p.kind,
                    route,
                });
            }
        }
    }
}

/// Next.js: `app/users/route.ts` -> GET/POST handlers; `app/users/page.tsx` -> page;
/// `pages/api/foo.ts` -> api route.
fn file_route_entry(rel: &str) -> Option<SurfaceEntry> {
    let name = rel.rsplit('/').next()?;
    let is_route = name == "route.ts" || name == "route.js";
    let is_page = name.starts_with("page.");
    let is_api = rel.starts_with("pages/api/");
    if !(is_route || is_page || is_api) {
        return None;
    }
    let route_path = rel
        .trim_start_matches("src/")
        .trim_start_matches("app/")
        .trim_start_matches("pages/api/")
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("");
    let route = format!(
        "/{}",
        route_path.trim_end_matches("/page").trim_matches('/')
    );
    Some(SurfaceEntry {
        file: rel.to_string(),
        line: 1,
        symbol: if is_api {
            "pages-api-route"
        } else if is_route {
            "app-route-handler"
        } else {
            "app-page"
        }
        .to_string(),
        kind: EntryKind::Http,
        route: Some(route),
    })
}
