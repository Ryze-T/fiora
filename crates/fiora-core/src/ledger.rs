//! `Ledger` — L0 state core (DESIGN.md §2).
//!
//! Layout under the base dir (`.fiora/`):
//!   files/<path>.json     file account book (candidates + analysis history)
//!   findings/<id>.json    first-class findings
//!   chains/<id>.json      first-class exploit chains
//!   evidence/<id>.json    deterministic evidence attachments
//!   runs/<runId>.json     run metadata + cost accounting
//!
//! Merge semantics (P4, append-only):
//!   - collections dedupe by stable id and never delete;
//!   - same id again = additive fill of missing fields only, never overwrite;
//!   - analysis history is pure append.
//!
//! Concurrency: atomic tmp+rename writes; claim via TTL lease (crash-safe:
//! an expired lease returns the file to the pending pool automatically).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::*;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&data).map_err(io::Error::other)?))
}

static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let uniq = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.tmp-{}-{}", std::process::id(), uniq));
    fs::write(
        &tmp,
        serde_json::to_string_pretty(value).map_err(io::Error::other)?,
    )?;
    fs::rename(&tmp, path)?;
    Ok(())
}

// ---------- additive-fill merge helpers ----------

fn merge_candidates(base: &mut Vec<Candidate>, incoming: Vec<Candidate>) {
    for c in incoming {
        let mut matched = false;
        for e in base.iter_mut() {
            if e.id == c.id {
                matched = true;
                if e.note.is_none() {
                    e.note = c.note.clone();
                }
                if e.evidence_id.is_none() {
                    e.evidence_id = c.evidence_id.clone();
                }
            }
        }
        if !matched {
            base.push(c);
        }
    }
    dedupe_by_id(base);
}

/// 同 id 只留一条：重复条目会永远缺字段（合并只填第一条），每次 run 重试。
fn dedupe_by_id(list: &mut Vec<Candidate>) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    list.retain(|c| seen.insert(c.id.clone()));
}

pub struct Ledger {
    base: PathBuf,
    /// Serializes read-modify-write records (run cost) across in-process workers.
    rmw_lock: std::sync::Mutex<()>,
}

impl Ledger {
    pub fn open(base: impl AsRef<Path>) -> io::Result<Self> {
        let base = base.as_ref().to_path_buf();
        for sub in ["files", "findings", "chains", "evidence", "runs"] {
            fs::create_dir_all(base.join(sub))?;
        }
        Ok(Ledger {
            base,
            rmw_lock: std::sync::Mutex::new(()),
        })
    }

    /// Base dir of the ledger (`.../.fiora`).
    pub fn base_dir(&self) -> &Path {
        &self.base
    }

    // ---------- file account book ----------

    fn file_path(&self, rel: &str) -> PathBuf {
        self.base.join("files").join(format!("{rel}.json"))
    }

    pub fn load_file(&self, rel: &str) -> io::Result<Option<FileRecord>> {
        read_json(&self.file_path(rel))
    }

    pub fn save_file(&self, rec: &FileRecord) -> io::Result<()> {
        write_json(&self.file_path(&rec.path), rec)
    }

    /// Create the file record if missing; existing collections are never clobbered.
    pub fn init_file(&self, rel: &str) -> io::Result<FileRecord> {
        let rec = match self.load_file(rel)? {
            Some(existing) => existing,
            None => FileRecord::new(rel),
        };
        self.save_file(&rec)?;
        Ok(rec)
    }

    pub fn merge_candidates(
        &self,
        rel: &str,
        candidates: Vec<Candidate>,
    ) -> io::Result<FileRecord> {
        let mut rec = self.load_file(rel)?.unwrap_or_else(|| FileRecord::new(rel));
        // 增量语义：合并引入新候选 id 时，已分析文件必须重新入审，
        // 否则新规则/新探索的候选永远得不到判定。
        let before: std::collections::BTreeSet<String> =
            rec.candidates.iter().map(|c| c.id.clone()).collect();
        merge_candidates(&mut rec.candidates, candidates);
        let has_new = rec.candidates.iter().any(|c| !before.contains(&c.id));
        if has_new && rec.status == FileStatus::Analyzed {
            rec.status = FileStatus::Pending;
        }
        self.save_file(&rec)?;
        Ok(rec)
    }

    /// Rule-channel refresh: the hits produced by *this* run are authoritative
    /// for the files it scanned. Candidates from other channels stay additive.
    ///
    /// Why additive is wrong here: a candidate id is (slug, file, line), so a
    /// rule that was removed or narrowed leaves orphans behind forever — dead
    /// rows in the report and, worse, paid triage of a hit no rule stands behind
    /// any more. `note` / `evidence_id` are carried over for ids that still hit,
    /// so L2 work is never thrown away by a rescan.
    pub fn replace_rule_candidates(
        &self,
        rel: &str,
        incoming: Vec<Candidate>,
    ) -> io::Result<FileRecord> {
        let mut rec = self.load_file(rel)?.unwrap_or_else(|| FileRecord::new(rel));
        let previous: BTreeMap<String, Candidate> = rec
            .candidates
            .iter()
            .filter(|c| c.channel == CandidateChannel::Rule)
            .map(|c| (c.id.clone(), c.clone()))
            .collect();
        let mut kept: Vec<Candidate> = rec
            .candidates
            .iter()
            .filter(|c| c.channel != CandidateChannel::Rule)
            .cloned()
            .collect();

        let before: BTreeSet<String> = previous.keys().cloned().collect();
        let mut fresh = incoming;
        for c in &mut fresh {
            if let Some(old) = previous.get(&c.id) {
                if c.note.is_none() {
                    c.note = old.note.clone();
                }
                if c.evidence_id.is_none() {
                    c.evidence_id = old.evidence_id.clone();
                }
            }
        }
        let after: BTreeSet<String> = fresh.iter().map(|c| c.id.clone()).collect();
        kept.extend(fresh);
        dedupe_by_id(&mut kept);
        rec.candidates = kept;
        // A changed rule set means the file's verdict may not hold any more.
        if before != after && rec.status == FileStatus::Analyzed {
            rec.status = FileStatus::Pending;
        }
        self.save_file(&rec)?;
        Ok(rec)
    }

    /// Pure append: analysis history is never overwritten.
    pub fn append_analysis(&self, rel: &str, entry: AnalysisEntry) -> io::Result<FileRecord> {
        let mut rec = self.load_file(rel)?.unwrap_or_else(|| FileRecord::new(rel));
        rec.analysis_history.push(entry);
        self.save_file(&rec)?;
        Ok(rec)
    }

    // ---------- audit provenance (report metadata) ----------

    fn audit_meta_path(&self) -> PathBuf {
        self.base.join("audit-meta.json")
    }

    pub fn load_audit_meta(&self) -> io::Result<Option<AuditMeta>> {
        read_json(&self.audit_meta_path())
    }

    /// Record a stage (+ its model) into the run provenance. Append-only merge:
    /// re-running a stage never erases earlier models or scopes.
    pub fn record_audit_stage(
        &self,
        stage: &str,
        model: Option<&str>,
        severity_scope: &str,
    ) -> io::Result<AuditMeta> {
        let _guard = self.rmw_lock.lock().unwrap();
        let mut meta = self
            .load_audit_meta()?
            .unwrap_or_else(|| AuditMeta::new(severity_scope));
        meta.record(stage, model);
        meta.severity_scope = severity_scope.to_string();
        write_json(&self.audit_meta_path(), &meta)?;
        Ok(meta)
    }

    // ---------- findings (first-class) ----------

    fn finding_path(&self, id: &str) -> PathBuf {
        self.base.join("findings").join(format!("{id}.json"))
    }

    pub fn load_finding(&self, id: &str) -> io::Result<Option<Finding>> {
        read_json(&self.finding_path(id))
    }

    /// Additive upsert: same id merges — missing Option fields are filled from
    /// the incoming finding, existing values are never overwritten; chain ids
    /// union. Re-running with a different model = strict improvement (P4).
    pub fn upsert_finding(&self, f: Finding) -> io::Result<Finding> {
        let path = self.finding_path(&f.id);
        match read_json::<Finding>(&path)? {
            Some(mut existing) => {
                if existing.data_flow.is_none() {
                    existing.data_flow = f.data_flow;
                }
                if existing.evidence_ref.is_none() {
                    existing.evidence_ref = f.evidence_ref;
                }
                if existing.repro_pack.is_none() {
                    existing.repro_pack = f.repro_pack;
                }
                if existing.verdict.is_none() {
                    existing.verdict = f.verdict;
                }
                if existing.agent.is_none() {
                    existing.agent = f.agent;
                }
                for cid in f.chain_ids {
                    if !existing.chain_ids.contains(&cid) {
                        existing.chain_ids.push(cid);
                    }
                }
                write_json(&path, &existing)?;
                Ok(existing)
            }
            None => {
                write_json(&path, &f)?;
                Ok(f)
            }
        }
    }

    pub fn list_finding_ids(&self) -> io::Result<Vec<String>> {
        self.list_ids("findings")
    }

    /// Explicit human-text rewrite (localization) — overwrites display fields
    /// only (title/description/reasoning/notes). Identity fields are untouched.
    pub fn rewrite_text(
        &self,
        id: &str,
        title: Option<&str>,
        description: Option<&str>,
        reasoning: Option<&str>,
        notes: Option<&str>,
    ) -> io::Result<Option<Finding>> {
        self.rewrite_text_full(id, title, description, reasoning, notes, None, None)
    }

    /// Like `rewrite_text`, and can also fill `impact` and `repro_pack`
    /// (used by `fiora enrich`).
    #[allow(clippy::too_many_arguments)]
    pub fn rewrite_text_full(
        &self,
        id: &str,
        title: Option<&str>,
        description: Option<&str>,
        reasoning: Option<&str>,
        notes: Option<&str>,
        impact: Option<&str>,
        repro_pack: Option<ReproPack>,
    ) -> io::Result<Option<Finding>> {
        let path = self.finding_path(id);
        match read_json::<Finding>(&path)? {
            Some(mut f) => {
                if let Some(t) = title {
                    f.title = t.to_string();
                }
                if let Some(d) = description {
                    f.description = d.to_string();
                }
                if let Some(i) = impact {
                    f.impact = Some(i.to_string());
                }
                if let Some(r) = repro_pack {
                    f.repro_pack = Some(r);
                }
                if let Some(r) = reasoning {
                    if let Some(v) = f.verdict.as_mut() {
                        v.reasoning = r.to_string();
                    }
                }
                if let Some(n) = notes {
                    if let Some(v) = f.verdict.as_mut() {
                        v.rebuttals.notes = n.to_string();
                    }
                }
                write_json(&path, &f)?;
                Ok(Some(f))
            }
            None => Ok(None),
        }
    }

    /// Explicit verdict update — revalidation is an UPDATE operation and may
    /// flip a verdict (unlike ordinary merge, which is additive-only).
    pub fn set_verdict(&self, id: &str, verdict: Verdict) -> io::Result<Option<Finding>> {
        let path = self.finding_path(id);
        match read_json::<Finding>(&path)? {
            Some(mut f) => {
                f.verdict = Some(verdict);
                write_json(&path, &f)?;
                Ok(Some(f))
            }
            None => Ok(None),
        }
    }

    /// Explicit verification update (L4) — verification is an UPDATE operation.
    pub fn set_verification(
        &self,
        id: &str,
        verification: Verification,
    ) -> io::Result<Option<Finding>> {
        let path = self.finding_path(id);
        match read_json::<Finding>(&path)? {
            Some(mut f) => {
                f.verification = Some(verification);
                write_json(&path, &f)?;
                Ok(Some(f))
            }
            None => Ok(None),
        }
    }

    /// 按验证结论校正严重度（verify record 的 --severity 入口）。
    pub fn set_finding_severity(
        &self,
        id: &str,
        severity: crate::types::Severity,
    ) -> io::Result<Option<Finding>> {
        let path = self.finding_path(id);
        match read_json::<Finding>(&path)? {
            Some(mut f) => {
                f.severity = severity;
                write_json(&path, &f)?;
                Ok(Some(f))
            }
            None => Ok(None),
        }
    }

    /// Link a finding into a chain (union, additive).
    pub fn link_chain(&self, finding_id: &str, chain_id: &str) -> io::Result<Option<Finding>> {
        let path = self.finding_path(finding_id);
        match read_json::<Finding>(&path)? {
            Some(mut f) => {
                if !f.chain_ids.iter().any(|c| c == chain_id) {
                    f.chain_ids.push(chain_id.to_string());
                }
                write_json(&path, &f)?;
                Ok(Some(f))
            }
            None => Ok(None),
        }
    }

    // ---------- chains (first-class, cross-file) ----------

    fn chain_path(&self, id: &str) -> PathBuf {
        self.base.join("chains").join(format!("{id}.json"))
    }

    pub fn load_chain(&self, id: &str) -> io::Result<Option<Chain>> {
        read_json(&self.chain_path(id))
    }

    pub fn upsert_chain(&self, c: Chain) -> io::Result<Chain> {
        write_json(&self.chain_path(&c.id), &c)?;
        Ok(c)
    }

    pub fn list_chain_ids(&self) -> io::Result<Vec<String>> {
        self.list_ids("chains")
    }

    // ---------- evidence (deterministic artifacts) ----------

    fn evidence_path(&self, id: &str) -> PathBuf {
        self.base.join("evidence").join(format!("{id}.json"))
    }

    pub fn save_evidence(&self, e: &Evidence) -> io::Result<()> {
        write_json(&self.evidence_path(&e.id), e)
    }

    pub fn load_evidence(&self, id: &str) -> io::Result<Option<Evidence>> {
        read_json(&self.evidence_path(id))
    }

    // ---------- run metadata / cost accounting ----------

    fn run_path(&self, run_id: &str) -> PathBuf {
        self.base.join("runs").join(format!("{run_id}.json"))
    }

    pub fn record_cost(&self, run_id: &str, cost: &Cost, at: &str) -> io::Result<RunMeta> {
        let _guard = self.rmw_lock.lock().unwrap();
        let path = self.run_path(run_id);
        let mut meta = read_json::<RunMeta>(&path)?.unwrap_or_else(|| RunMeta {
            run_id: run_id.to_string(),
            started_at: at.to_string(),
            cost: Cost::zero(),
            notes: Vec::new(),
        });
        meta.cost.merge(cost);
        write_json(&path, &meta)?;
        Ok(meta)
    }

    // ---------- scheduling: TTL lease, resumable ----------

    /// All known file paths (relative, sorted).
    pub fn list_files(&self) -> io::Result<Vec<String>> {
        Ok(
            crate::fsutil::list_files(&self.base.join("files"), &["json"])?
                .into_iter()
                .map(|(rel, _)| rel.trim_end_matches(".json").to_string())
                .collect(),
        )
    }

    fn list_ids(&self, sub: &str) -> io::Result<Vec<String>> {
        Ok(crate::fsutil::list_files(&self.base.join(sub), &["json"])?
            .into_iter()
            .map(|(rel, _)| rel.trim_end_matches(".json").to_string())
            .collect())
    }

    /// Pending = status pending AND not leased. This is the resume point.
    /// 待判定队列 = Pending + 复跑池。
    ///
    /// 复跑池：判定会话产出非 JSON（拒答）且无任何 finding 的文件——
    /// 它们的候选**从未被裁决**，必须自动重新入审（静默损失防线）。
    pub fn pending(&self) -> io::Result<Vec<String>> {
        let now = now_ms();
        let mut out = Vec::new();
        for rel in self.list_files()? {
            if let Some(rec) = self.load_file(&rel)? {
                if rec.status == FileStatus::Pending && !rec.is_locked(now) {
                    out.push(rel);
                    continue;
                }
                if rec.status == FileStatus::Analyzed && !rec.candidates.is_empty() {
                    // 只看最新条目：旧拒答已被后续成功裁决覆盖时不得重复入审
                    let never_adjudicated = rec
                        .analysis_history
                        .last()
                        .map(|h| h.refused == Some(true) && h.finding_ids.is_empty())
                        .unwrap_or(false);
                    if never_adjudicated && !rec.is_locked(now) {
                        out.push(rel);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Claim pending files for `run_id` under a TTL lease. Already leased or
    /// non-pending files are skipped (multi-worker safe on one host).
    pub fn claim(
        &self,
        rel_paths: &[String],
        run_id: &str,
        ttl: Duration,
    ) -> io::Result<(Vec<String>, Vec<String>)> {
        let expires = now_ms() + ttl.as_millis() as u64;
        let mut claimed = Vec::new();
        let mut skipped = Vec::new();
        for rel in rel_paths {
            match self.load_file(rel)? {
                Some(mut rec) if rec.status == FileStatus::Pending && !rec.is_locked(now_ms()) => {
                    rec.locked_by_run_id = Some(run_id.to_string());
                    rec.lease_expires_at = Some(expires);
                    self.save_file(&rec)?;
                    claimed.push(rel.clone());
                }
                _ => skipped.push(rel.clone()),
            }
        }
        Ok((claimed, skipped))
    }

    /// Renew the lease of claimed work (heartbeat).
    pub fn heartbeat(&self, rel_paths: &[String], run_id: &str, ttl: Duration) -> io::Result<()> {
        let expires = now_ms() + ttl.as_millis() as u64;
        for rel in rel_paths {
            if let Some(mut rec) = self.load_file(rel)? {
                if rec.locked_by_run_id.as_deref() == Some(run_id) {
                    rec.lease_expires_at = Some(expires);
                    self.save_file(&rec)?;
                }
            }
        }
        Ok(())
    }

    /// Finish analysis: write terminal status and release the lease.
    pub fn complete(&self, rel: &str, status: FileStatus) -> io::Result<FileRecord> {
        let mut rec = self
            .load_file(rel)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, rel.to_string()))?;
        rec.status = status;
        rec.locked_by_run_id = None;
        rec.lease_expires_at = None;
        self.save_file(&rec)?;
        Ok(rec)
    }

    /// Crash recovery: release every stale lock held by `run_id`.
    pub fn release_run(&self, run_id: &str) -> io::Result<Vec<String>> {
        let mut released = Vec::new();
        for rel in self.list_files()? {
            if let Some(mut rec) = self.load_file(&rel)? {
                if rec.locked_by_run_id.as_deref() == Some(run_id) {
                    rec.locked_by_run_id = None;
                    rec.lease_expires_at = None;
                    self.save_file(&rec)?;
                    released.push(rel);
                }
            }
        }
        Ok(released)
    }
}
