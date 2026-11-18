//! `fiora-processor` — L3 judgment pipeline (DESIGN.md §5).
//!
//! Owns the pi driver (the single audit agent runtime), prompt assembly
//! (runtime-overridable data), the semantic self-mining channel, the
//! triage/judge/revalidate pipeline, the verdict contract, and the chain engine.

pub mod bootstrap;
pub mod chain;
pub mod compose;
pub mod guard_check;
pub mod pi;
pub mod pipeline;
pub mod prompts;
pub mod semantic;
pub mod trace;
pub mod verdict;

pub use bootstrap::{patch_models_json, protocol_for, provider_env_for, spawn_env};
pub use chain::{compose_chains, persist_chains};
pub use compose::{
    build_inventory, compose_prompt, compose_verify_prompt, parse_compositions, Observation,
};
pub use pi::{parse_event_stream, PiError, PiOutcome, PiRequest, PiRunner, ThinkingLevel};
pub use pipeline::{
    load_info_md, process_pending, PipelineError, ProcessConfig, ProcessSummary, RunContext,
};
pub use prompts::{json_repair_prompt, load_or_default, SEMANTIC_EXPLORE_BUILTIN};
pub use semantic::{
    parse_findings, parse_plan, ExploreBudget, HuntHypothesis, SemanticChannel, SemanticFinding,
};
pub use trace::{find_session_file, parse_session, render_trace, AuditTrace, TraceEvent};
pub use verdict::{
    into_core, parse_judge_output, parse_severity, run_json_with_repair, JudgeFinding, JudgeOutput,
};
