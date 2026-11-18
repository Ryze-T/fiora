//! `fiora-scanner` — L1 candidate generation, dual channel (DESIGN.md §3).
//!
//! Channel A (rule): embedded OpenGrep engine over the three-layer Fiora Rules
//! corpus -> normalized candidates. Channel B (semantic): pi-agent self-mining
//! outside covered paths (budget-quota exploration) — the runner lives in
//! `fiora-processor` (it drives pi sessions); this crate owns the corpus,
//! normalization, tech detection and the surface inventory.
//!
//! There is exactly ONE rule engine: Semgrep-compatible YAML loaded through the
//! three-level registry (builtin < user < project). Model-authored rules are
//! written as ordinary rule YAML via `fiora rules add`, so they go through the
//! same validation and the same engine — no second matcher language.

pub mod normalize;
pub mod opengrep;
pub mod profile;
pub mod rules;
pub mod surface;
pub mod tech;

pub use normalize::{normalize, parse_json, OpgrepReport};
pub use profile::detect_profile_tags;
pub use rules::{sync_builtin_copies, BuiltinSync, LoadedRule, RuleRegistry, RuleSource};
pub use surface::{enumerate as enumerate_surface, EntryKind, SurfaceEntry};
pub use tech::{detect as detect_tech, TechReport};
