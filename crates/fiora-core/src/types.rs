//! Fiora core data model (DESIGN.md §8).
//!
//! Three-entity audit ledger: FileRecord (file account book) / Finding (vulnerability)
//! / Chain (exploit chain, first-class, cross-file), plus Evidence attachments.
//!
//! Identity rules (P4): Finding identity = hash(category slug, sink symbol, enclosing
//! function) — title and line numbers are display-only so re-running with a different
//! model merges instead of duplicating.

use serde::{Deserialize, Serialize};

// ---------- severities ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    /// Non-security bug that could cause data loss, corruption, outages.
    HighBug,
    /// Notable non-security bug.
    Bug,
}

impl Severity {
    /// Canonical ordering for sorting/composition (single source of truth).
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            _ => 1,
        }
    }
}

// ---------- L1 candidates ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateChannel {
    Rule,
    Semantic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub id: String,
    pub slug: String,
    pub matcher_id: String,
    pub channel: CandidateChannel,
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Filled by L2 evidence pre-assembly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

// ---------- L2 evidence (deterministic artifacts) ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeAnchor {
    pub symbol: String,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryAnchor {
    pub symbol: String,
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HopQuality {
    /// Compiler-grade resolution (e.g. Go x/tools VTA).
    Compiler,
    /// Traced by the agent with code coordinates (protocol-verified).
    Traced,
    /// Resolved by LLM semantic inference.
    Llm,
    /// Unresolved (reflection/dynamic dispatch) — transparently exposed.
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHop {
    pub from: String,
    pub to: String,
    pub quality: HopQuality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceGrade {
    DataflowVerified,
    CallchainVerified,
    Inferred,
    DeadCode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub id: String,
    pub sink: CodeAnchor,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<CodeAnchor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<EntryAnchor>,
    /// entry -> ... -> sink, one hop per step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_chain: Vec<CallHop>,
    pub grade: EvidenceGrade,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_hops: Vec<String>,
    pub tool: String,
}

// ---------- L3 verdicts ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictConclusion {
    TruePositive,
    FalsePositive,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// The six-question mandatory rebuttal (vuln-mining §3.2). `None` = not assessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebuttalAnswers {
    /// Is it parameterized? (parameterized query / safe API -> not injectable)
    pub parameterized: Option<bool>,
    /// Is it reachable? (HTTP entry exists? dead code?)
    pub reachable: Option<bool>,
    /// Is this a business method rather than a dangerous API?
    pub business_method: Option<bool>,
    /// Allowlist / enum / regex constraint present?
    pub allowlisted: Option<bool>,
    /// Is the input genuinely user-controlled? (constant/config != user input)
    pub user_input_controlled: Option<bool>,
    /// Is there a guard? (escape function / security check invoked?)
    pub protected_by_guard: Option<bool>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub conclusion: VerdictConclusion,
    pub confidence: Confidence,
    /// Must reference Evidence.id — conclusions hang on evidence (P2).
    pub evidence_ref: Option<String>,
    pub rebuttals: RebuttalAnswers,
    pub reasoning: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproStatus {
    Verified,
    Inferred,
    Todo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReproPack {
    pub preconditions: Vec<String>,
    pub request: String,
    pub expected: String,
    pub actual: String,
    pub status: ReproStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cost {
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub usd: f64,
}

impl Cost {
    pub fn zero() -> Self {
        Cost {
            tokens_in: 0,
            tokens_out: 0,
            usd: 0.0,
        }
    }

    pub fn merge(&mut self, other: &Cost) {
        self.tokens_in += other.tokens_in;
        self.tokens_out += other.tokens_out;
        self.usd += other.usd;
    }
}

impl Default for Cost {
    fn default() -> Self {
        Cost::zero()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProvenance {
    pub backend: String,
    pub model: String,
    pub thinking_level: String,
    pub run_id: String,
    /// pi 持久会话 id——`pi --resume <id>` 可回看完整推理（durable 证据链）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
}

// ---------- Finding (first-class entity) ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    /// "static-diff" | "exec-diff" | "fix-check"
    pub method: String,
    pub pre_state: String,
    pub post_state: String,
    /// "fixed" | "persisting" | "regressed" | "unknown"
    pub verdict: String,
    pub at: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Identity anchor: hash(category slug, sink symbol, enclosing function).
    pub id: String,
    pub slug: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// Identity anchor inputs — also the deterministic L4 probe needle.
    pub sink_symbol: String,
    pub enclosing_fn: String,
    /// The vulnerable *shape* (e.g. "db.Exec(fmt.Sprintf") — a sink symbol
    /// alone also matches safe variants, so L4 probes this construction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_shape: Option<String>,
    pub description: String,
    /// 可能造成的影响（危害分析）——报告一等区块
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    /// 触发前置条件（可达性轴）：默认可打 / 需某模式 / 需本地立足点 / 供应链语境…
    /// 风险评级 = 危害 × 可达性（REPORT-TEMPLATE.md 两轴定级）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_flow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro_pack: Option<ReproPack>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentProvenance>,
    /// L4 verification record (pre/post-patch differential or fix check).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

// ---------- Chain (first-class, cross-file) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainPattern {
    /// A's output feeds B's input.
    Dataflow,
    /// Low privilege -> high privilege.
    Privilege,
    /// Multiple small holes stack into a big capability.
    Stacking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainStep {
    pub finding_id: String,
    pub note: String,
}

/// 链的机制可达性（A2 传输层兼容检查产物）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChainReach {
    /// 步骤间机制直接可达
    #[default]
    Direct,
    /// 需要传输层桥接（如 HTTP SSRF 打不到裸 TCP 服务，需另寻立足点）
    TransportGap,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chain {
    pub id: String,
    pub title: String,
    pub pattern: ChainPattern,
    /// 机制可达性标注
    #[serde(default)]
    pub reach: ChainReach,
    pub steps: Vec<ChainStep>,
    /// Terminal impact, quantified (data+volume / RCE / takeover).
    pub impact: String,
    pub severity: Severity,
}

// ---------- FileRecord (file account book) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Pending,
    Analyzed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisEntry {
    pub run_id: String,
    pub agent: AgentProvenance,
    pub at: String,
    pub summary: String,
    pub finding_ids: Vec<String>,
    /// Refusal tracking: no silent skips (anti-leak discipline).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRecord {
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<Candidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analysis_history: Vec<AnalysisEntry>,
    pub status: FileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_by_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<u64>,
}

impl FileRecord {
    pub fn new(path: &str) -> Self {
        FileRecord {
            path: path.to_string(),
            candidates: Vec::new(),
            analysis_history: Vec::new(),
            status: FileStatus::Pending,
            locked_by_run_id: None,
            lease_expires_at: None,
        }
    }

    /// A file is locked only while its lease has not expired (crash-safe).
    pub fn is_locked(&self, now_ms: u64) -> bool {
        match (&self.locked_by_run_id, self.lease_expires_at) {
            (Some(_), Some(exp)) => exp > now_ms,
            _ => false,
        }
    }
}

// ---------- Run metadata (cost accounting) ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunMeta {
    pub run_id: String,
    pub started_at: String,
    pub cost: Cost,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

// ---------- Audit run metadata (report provenance) ----------

/// Provenance of the audit behind `fiora-report/report.*` — written by the
/// stages that spend model calls (`process` / `explore`) and read by `report`.
///
/// The report must never assert how it was produced from hardcoded strings:
/// the agent label and method line come from here, so a report generated with
/// `--model openai/gpt-5` cannot claim to be a mimo run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditMeta {
    /// Distinct model identifiers that produced judgments (in first-seen order).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// Severity scope the run was limited to (`high` | `all`).
    pub severity_scope: String,
    /// Stages that ran (`scan` / `explore` / `process` / `revalidate`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
    pub updated_at: String,
}

impl AuditMeta {
    pub fn new(severity_scope: &str) -> Self {
        AuditMeta {
            models: Vec::new(),
            severity_scope: severity_scope.to_string(),
            stages: Vec::new(),
            updated_at: crate::util::now_iso(),
        }
    }

    /// Record a stage + the model it used (idempotent, append-only order).
    pub fn record(&mut self, stage: &str, model: Option<&str>) {
        if !self.stages.iter().any(|s| s == stage) {
            self.stages.push(stage.to_string());
        }
        if let Some(m) = model {
            if !m.is_empty() && !self.models.iter().any(|x| x == m) {
                self.models.push(m.to_string());
            }
        }
        self.updated_at = crate::util::now_iso();
    }
}
