//! Fiora Rules — three-level, user-maintainable rule corpus (DESIGN.md §3).
//!
//! Precedence low -> high: builtin (bundled, read-only) < user (`~/.fiora/rules/`)
//! < project (`.fiora/rules/`, git-shared). A higher level overrides a lower one
//! with the same rule id — teams can narrow noisy builtin rules by re-declaring
//! the id. Rules are plain Semgrep YAML, loaded at runtime (P8: data-driven).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fiora_core::id::stable_id;
use serde::{Deserialize, Serialize};

/// Built-in rules embedded in the binary.
pub const BUILTIN_RULES: &[(&str, &str)] = &[
    ("auth.yaml", include_str!("../rules/builtin/auth.yaml")),
    ("cmdi.yaml", include_str!("../rules/builtin/cmdi.yaml")),
    ("rce.yaml", include_str!("../rules/builtin/rce.yaml")),
    ("sqli.yaml", include_str!("../rules/builtin/sqli.yaml")),
    (
        "coverage-floor.yaml",
        include_str!("../rules/builtin/coverage-floor.yaml"),
    ),
    ("taint.yaml", include_str!("../rules/builtin/taint.yaml")),
    (
        "k8s-takeover.yaml",
        include_str!("../rules/builtin/k8s-takeover.yaml"),
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    Builtin,
    User,
    Project,
}

impl RuleSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleSource::Builtin => "builtin",
            RuleSource::User => "user",
            RuleSource::Project => "project",
        }
    }
}

/// One rule as we understand it. Pattern fields stay opaque — OpenGrep compiles
/// them; we only need identity/metadata for listing, validation and coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub metadata: Option<serde_yaml::Value>,
}

fn default_severity() -> String {
    "WARNING".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RulesFile {
    rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadedRule {
    pub source: RuleSource,
    /// File it came from, relative to its level (e.g. `builtin/cmdi.yaml`).
    pub file: String,
    pub spec: RuleSpec,
}

impl LoadedRule {
    /// Where a rule really comes from, for humans. A copy of a bundled rule that
    /// lives at the user level was not hand-written by the user, and calling all
    /// 87 of them "user" makes `rules list` useless for finding your own rules.
    pub fn origin(&self) -> &'static str {
        match (&self.source, self.file.starts_with("builtin/")) {
            (RuleSource::User, true) => "copy",
            _ => self.source.as_str(),
        }
    }
}

#[derive(Debug, Default)]
pub struct RuleRegistry {
    /// id -> rule; higher-precedence sources overwrite the slot.
    rules: BTreeMap<String, LoadedRule>,
    /// (source, filename, yaml text) —— 供 config_dirs 三级全部物化进扫描。
    files: Vec<(RuleSource, String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("rule validation failed: {0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl RuleRegistry {
    /// Load the full three-level corpus: builtin < user dir < project dir.
    pub fn load(user_dir: Option<&Path>, project_dir: Option<&Path>) -> Result<Self, RuleError> {
        let mut reg = RuleRegistry::default();
        for (name, text) in BUILTIN_RULES {
            reg.load_yaml_text(RuleSource::Builtin, name, text)?;
        }
        if let Some(dir) = user_dir {
            reg.load_dir(RuleSource::User, dir)?;
        }
        if let Some(dir) = project_dir {
            reg.load_dir(RuleSource::Project, dir)?;
        }
        Ok(reg)
    }

    fn load_dir(&mut self, source: RuleSource, dir: &Path) -> Result<(), RuleError> {
        if !dir.is_dir() {
            return Ok(());
        }
        // 名字用相对路径而不是裸文件名：同一级目录下两层都有 `cmdi.yaml` 时，
        // 裸文件名会在物化阶段互相覆盖（低级的规则静默消失）。
        for (rel, path) in fiora_core::fsutil::list_files(dir, &["yaml", "yml"])? {
            let text = fs::read_to_string(&path)?;
            self.load_yaml_text(source, &rel, &text)?;
        }
        Ok(())
    }

    fn load_yaml_text(
        &mut self,
        source: RuleSource,
        name: &str,
        text: &str,
    ) -> Result<(), RuleError> {
        self.files
            .push((source, name.to_string(), text.to_string()));
        let file: RulesFile = serde_yaml::from_str(text)?;
        for spec in file.rules {
            validate(&spec, name)?;
            self.rules.insert(
                spec.id.clone(),
                LoadedRule {
                    source,
                    file: name.to_string(),
                    spec,
                },
            );
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&LoadedRule> {
        self.rules.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &LoadedRule> {
        self.rules.values()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Directories OpenGrep should scan with, lowest precedence first.
    /// 三级规则物化为 opengrep config 目录（builtin < user < project），每级
    /// 只落**真正获胜**的规则（opengrep 对多个 `--config` 目录取并集，同 id
    /// 不互相覆盖，原样全落等于「覆盖」承诺落空）。落盘前清空本级目录，
    /// 且一律经 `render_yaml` 转 ASCII（引擎按默认 codec 读配置，非 ASCII
    /// 字节会让整次扫描静默失败），转码只把非 ASCII 写成 `\uXXXX` 转义。
    pub fn config_dirs(&self, cache_dir: &Path) -> Result<Vec<PathBuf>, RuleError> {
        let mut dirs = Vec::new();
        for source in [RuleSource::Builtin, RuleSource::User, RuleSource::Project] {
            let dir = cache_dir.join(source.as_str());
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
            }
            fs::create_dir_all(&dir)?;
            let mut any = false;
            for (src, name, text) in &self.files {
                if *src != source {
                    continue;
                }
                let winners = |id: &str| self.rules.get(id).map(|r| r.source) == Some(source);
                let Some(body) = render_yaml(text, &winners) else {
                    // Every rule in this file was shadowed at a higher level.
                    continue;
                };
                let dest = dir.join(name);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(dest, body)?;
                any = true;
            }
            if any {
                dirs.push(dir);
            }
        }
        Ok(dirs)
    }
}

/// Re-encode a rule file as ASCII-only YAML without changing what it means.
///
/// JSON is a subset of YAML, and every JSON string is double-quoted — which is
/// exactly the form that admits `\uXXXX` / `\UXXXXXXXX` escapes. So: parse the
/// rule document, serialize it as JSON, then escape every non-ASCII scalar char.
/// Strings, numbers, booleans, nesting and unknown rule fields all survive; only
/// comments (irrelevant to the engine) are dropped.
#[cfg(test)]
fn ascii_safe_yaml(text: &str) -> Option<String> {
    render_yaml(text, &|_| true)
}

/// Transcode one rule file to ASCII and keep only the rules `keep` accepts.
///
/// Returns `None` when nothing survives — a config file whose rules were all
/// shadowed at another level must not reach the engine at all.
fn render_yaml(text: &str, keep: &dyn Fn(&str) -> bool) -> Option<String> {
    let mut doc: serde_yaml::Value = serde_yaml::from_str(text).ok()?;
    let rules = doc
        .as_mapping_mut()?
        .get_mut(serde_yaml::Value::String("rules".to_string()))?
        .as_sequence_mut()?;
    rules.retain(|rule| match rule.get("id").and_then(|v| v.as_str()) {
        Some(id) => keep(id),
        // No id = not a rule we could shadow; let validation complain about it.
        None => true,
    });
    if rules.is_empty() {
        return None;
    }
    let json = serde_json::to_string(&doc).ok()?;
    Some(escape_non_ascii(&json))
}

fn escape_non_ascii(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let cp = ch as u32;
            // JSON only has the 4-digit form (surrogate pairs), which YAML would
            // decode as lone surrogates — use YAML's own 8-digit escape instead.
            if cp <= 0xFFFF {
                out.push_str(&format!("\\u{cp:04X}"));
            } else {
                out.push_str(&format!("\\U{cp:08X}"));
            }
        }
    }
    out
}

/// Where the `builtin/` copies record what *we* last wrote there.
const CORPUS_STATE: &str = ".corpus-state";

/// Outcome of one corpus sync, so the caller can say what happened instead of
/// silently rewriting the user's rule directory.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BuiltinSync {
    /// Copies that were replaced by the bundled corpus (new install or upgrade).
    pub refreshed: Vec<String>,
    /// Copies that differ from both the bundled corpus and what we wrote last
    /// time — somebody edited them on purpose, so they win (and we say so).
    pub kept_customized: Vec<String>,
}

fn content_hash(text: &str) -> String {
    stable_id("rule", &[text])
}

/// Keep `<user_dir>/builtin/` in step with the corpus compiled into this binary.
///
/// Those copies are *editable* and they shadow the embedded rules (higher
/// precedence), so without sync every rule fix shipped in a new binary is
/// silently outvoted by the copy an older install wrote to disk. Sync keeps the
/// promise both ways:
///   - untouched copy of an older corpus → replaced (that's the upgrade);
///   - copy whose bytes we never wrote → kept, reported as customized.
///
/// A pre-state-file install (older fiora) cannot be distinguished from an edit,
/// so the previous bytes are kept next to it as `<name>.bak` before replacing.
pub fn sync_builtin_copies(user_dir: &Path) -> std::io::Result<BuiltinSync> {
    let dir = user_dir.join("builtin");
    fs::create_dir_all(&dir)?;
    let state_path = dir.join(CORPUS_STATE);
    let legacy_install = !state_path.exists();
    let mut recorded = read_state(&state_path);
    let mut out = BuiltinSync::default();

    for (name, text) in BUILTIN_RULES {
        let dest = dir.join(name);
        let disk = fs::read_to_string(&dest).ok();
        match disk {
            None => {
                fs::write(&dest, text)?;
                recorded.insert(name.to_string(), content_hash(text));
                out.refreshed.push(name.to_string());
            }
            Some(ref d) if d == text => {
                // Already current; just refresh the bookkeeping.
                recorded.insert(name.to_string(), content_hash(text));
            }
            Some(d) => {
                let untouched = recorded.get(*name) == Some(&content_hash(&d));
                if untouched || legacy_install {
                    if legacy_install {
                        // Never lose bytes we cannot explain.
                        let _ = fs::write(dir.join(format!("{name}.bak")), &d);
                    }
                    fs::write(&dest, text)?;
                    recorded.insert(name.to_string(), content_hash(text));
                    out.refreshed.push(name.to_string());
                } else {
                    out.kept_customized.push(name.to_string());
                }
            }
        }
    }

    write_state(&state_path, &recorded)?;
    Ok(out)
}

fn read_state(path: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            if let Some((name, hash)) = line.split_once('\t') {
                map.insert(name.to_string(), hash.to_string());
            }
        }
    }
    map
}

fn write_state(path: &Path, map: &BTreeMap<String, String>) -> std::io::Result<()> {
    let body: String = map.iter().map(|(n, h)| format!("{n}\t{h}\n")).collect();
    fs::write(path, body)
}

/// Structural validation (P8: bad rules are rejected before they ever run).
fn validate(spec: &RuleSpec, file: &str) -> Result<(), RuleError> {
    if spec.id.is_empty() {
        return Err(RuleError::Invalid(format!("{file}: rule with empty id")));
    }
    if spec.id.contains(char::is_whitespace) {
        return Err(RuleError::Invalid(format!(
            "{file}: rule id {:?} contains whitespace",
            spec.id
        )));
    }
    if spec.languages.is_empty() {
        return Err(RuleError::Invalid(format!(
            "{file}: rule {:?} declares no languages",
            spec.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> serde_yaml::Value {
        serde_yaml::from_str(text).expect("rule yaml parses")
    }

    /// The transcoded config must be pure ASCII *and* mean the same document.
    /// Both halves matter: ASCII is what keeps OpenGrep's reader alive, semantic
    /// equality is what keeps the rules the same rules.
    #[test]
    fn every_builtin_rule_file_transcodes_to_ascii_without_changing_meaning() {
        for (name, text) in BUILTIN_RULES {
            let body =
                ascii_safe_yaml(text).unwrap_or_else(|| panic!("{name}: transcoding failed"));
            assert!(
                body.is_ascii(),
                "{name}: transcoded config still has non-ASCII bytes"
            );
            assert_eq!(
                parse(&body),
                parse(text),
                "{name}: transcoding changed the rule document"
            );
        }
    }

    #[test]
    fn non_ascii_messages_survive_as_escapes() {
        let text = "rules:\n- id: x\n  languages: [go]\n  message: \"任意命令执行：exec.Command\"\n  severity: ERROR\n";
        let body = ascii_safe_yaml(text).expect("transcode");
        assert!(body.is_ascii());
        assert!(body.contains("\\u4EFB"), "expected \\u escape, got: {body}");
        let doc = parse(&body);
        let msg = doc["rules"][0]["message"].as_str().unwrap();
        assert_eq!(msg, "任意命令执行：exec.Command");
    }

    /// Astral-plane characters cannot use the 4-digit form (JSON surrogate pairs
    /// would decode as lone surrogates in YAML), so they must use `\U`.
    #[test]
    fn astral_characters_use_the_eight_digit_escape() {
        let text = "rules:\n- id: x\n  languages: [go]\n  message: \"boom \u{1F600}\"\n  severity: ERROR\n";
        let body = ascii_safe_yaml(text).expect("transcode");
        assert!(body.is_ascii());
        assert!(body.contains("\\U0001F600"), "got: {body}");
        let doc = parse(&body);
        assert_eq!(
            doc["rules"][0]["message"].as_str().unwrap(),
            "boom \u{1F600}"
        );
    }

    /// The level that wins an id must be the only place the engine sees it:
    /// opengrep unions `--config` directories, so materializing every level
    /// would silently turn "override" into "add both".
    #[test]
    fn higher_level_rule_replaces_the_lower_one_in_the_scanned_config() {
        let dir = std::env::temp_dir().join(format!("fiora-prec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let user = dir.join("user");
        fs::create_dir_all(user.join("builtin")).unwrap();
        // A user-level copy that re-declares a builtin id with a narrower pattern.
        fs::write(
            user.join("builtin/cmdi.yaml"),
            "rules:\n- id: cmdi-go-exec\n  languages: [go]\n  severity: ERROR\n  message: narrowed\n  pattern: sentinel_call(...)\n",
        )
        .unwrap();

        let reg = RuleRegistry::load(Some(&user), None).expect("load");
        let got = reg.get("cmdi-go-exec").expect("rule present");
        assert_eq!(got.source, RuleSource::User, "user copy must win the id");

        let cache = dir.join("cache");
        let dirs = reg.config_dirs(&cache).expect("materialize");
        let builtin_body = fs::read_to_string(cache.join("builtin/cmdi.yaml")).unwrap_or_default();
        assert!(
            !builtin_body.contains("cmdi-go-exec"),
            "the shadowed builtin rule must not reach the engine"
        );
        let user_body = fs::read_to_string(cache.join("user/builtin/cmdi.yaml")).unwrap();
        assert!(
            user_body.contains("sentinel_call"),
            "user version must survive"
        );
        assert_eq!(
            dirs,
            vec![cache.join("builtin"), cache.join("user")],
            "levels are handed over lowest-first"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Stale files from an earlier run must not keep participating in scans.
    #[test]
    fn config_dirs_clears_previous_materialization() {
        let dir = std::env::temp_dir().join(format!("fiora-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cache = dir.join("cache");
        fs::create_dir_all(cache.join("builtin")).unwrap();
        fs::write(cache.join("builtin/gone.yaml"), "rules: []").unwrap();

        let reg = RuleRegistry::load(None, None).expect("load");
        reg.config_dirs(&cache).expect("materialize");
        assert!(
            !cache.join("builtin/gone.yaml").exists(),
            "a rule deleted since the last run must not be scanned again"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A copy we wrote stays in step with the binary: an upgrade refreshes it.
    #[test]
    fn untouched_builtin_copy_is_refreshed_on_upgrade() {
        let dir = std::env::temp_dir().join(format!("fiora-sync-upgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let user = dir.join("rules");
        let builtin = user.join("builtin");
        fs::create_dir_all(&builtin).unwrap();

        // Simulate the previous release: an older text for cmdi.yaml that *we*
        // wrote (recorded in the state file), plus a fresh install state.
        let name = BUILTIN_RULES[0].0;
        let old = "rules:\n- id: stale\n  languages: [go]\n  severity: ERROR\n  pattern: x()\n";
        fs::write(builtin.join(name), old).unwrap();
        fs::write(
            builtin.join(CORPUS_STATE),
            format!("{name}\t{}\n", content_hash(old)),
        )
        .unwrap();

        let sync = sync_builtin_copies(&user).expect("sync");
        assert!(sync.refreshed.contains(&name.to_string()));
        assert!(sync.kept_customized.is_empty());
        assert_eq!(
            fs::read_to_string(builtin.join(name)).unwrap(),
            BUILTIN_RULES[0].1,
            "untouched copy must take the bundled corpus"
        );

        // Second run is a no-op: nothing to refresh, nothing to report.
        let again = sync_builtin_copies(&user).expect("sync again");
        assert!(again.refreshed.is_empty());
        assert!(again.kept_customized.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A deliberate edit is never overwritten — it is reported instead, because
    /// the copy wins over the bundled rule and the operator has to know that.
    #[test]
    fn customized_builtin_copy_is_kept_and_reported() {
        let dir = std::env::temp_dir().join(format!("fiora-sync-edit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let user = dir.join("rules");
        let builtin = user.join("builtin");
        fs::create_dir_all(&builtin).unwrap();

        let name = BUILTIN_RULES[0].0;
        // Install the current corpus first so the state file exists…
        sync_builtin_copies(&user).expect("install");
        // …then edit one copy the way a team narrowing a noisy rule would.
        let edited =
            "rules:\n- id: narrowed\n  languages: [go]\n  severity: WARNING\n  pattern: y()\n";
        fs::write(builtin.join(name), edited).unwrap();

        let sync = sync_builtin_copies(&user).expect("sync");
        assert_eq!(sync.kept_customized, vec![name.to_string()]);
        assert!(sync.refreshed.is_empty());
        assert_eq!(
            fs::read_to_string(builtin.join(name)).unwrap(),
            edited,
            "a deliberate edit must survive the sync"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Installs predating the state file cannot be told apart from edits, so the
    /// old bytes are preserved next to the refreshed file instead of vanishing.
    #[test]
    fn legacy_install_without_state_file_is_refreshed_with_a_backup() {
        let dir = std::env::temp_dir().join(format!("fiora-sync-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let user = dir.join("rules");
        let builtin = user.join("builtin");
        fs::create_dir_all(&builtin).unwrap();

        let name = BUILTIN_RULES[0].0;
        let old = "rules:\n- id: legacy\n  languages: [go]\n  severity: ERROR\n  pattern: z()\n";
        fs::write(builtin.join(name), old).unwrap();

        let sync = sync_builtin_copies(&user).expect("sync");
        assert!(sync.refreshed.contains(&name.to_string()));
        assert_eq!(
            fs::read_to_string(builtin.join(format!("{name}.bak"))).unwrap(),
            old,
            "legacy bytes must be kept as a .bak"
        );
        assert_eq!(
            fs::read_to_string(builtin.join(name)).unwrap(),
            BUILTIN_RULES[0].1
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_dirs_materializes_every_level_as_ascii() {
        let dir = std::env::temp_dir().join(format!("fiora-rules-ascii-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let reg = RuleRegistry::load(None, None).expect("builtin rules load");
        let dirs = reg.config_dirs(&dir).expect("materialize");
        assert!(!dirs.is_empty());
        for d in dirs {
            for entry in fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                assert!(
                    bytes.is_ascii(),
                    "{}: materialized config must be ASCII",
                    path.display()
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
