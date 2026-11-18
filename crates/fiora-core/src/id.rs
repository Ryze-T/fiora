//! Stable identity for append-only merge (P4).
//!
//! Finding identity deliberately excludes title and line number: wording changes
//! across models and line numbers drift across edits. Identity is anchored on
//! (category slug, sink symbol, enclosing function) so a re-run with a different
//! model merges into the same finding instead of duplicating it.

use sha1::{Digest, Sha1};

/// 12 hex chars (48 bits) of SHA-1 — compact and collision-safe for our scale.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(prefix.as_bytes());
    for p in parts {
        hasher.update(b"|");
        hasher.update(p.as_bytes());
    }
    let bytes = hasher.finalize();
    bytes[..6].iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn candidate_id(slug: &str, file: &str, line: u32) -> String {
    stable_id("c", &[slug, file, &line.to_string()])
}

/// Identity anchor: category slug + sink symbol + enclosing function signature.
pub fn finding_id(category: &str, sink_symbol: &str, enclosing_fn: &str) -> String {
    stable_id("f", &[category, sink_symbol, enclosing_fn])
}

pub fn evidence_id(sink_symbol: &str, sink_file: &str, sink_line: u32) -> String {
    stable_id("e", &[sink_symbol, sink_file, &sink_line.to_string()])
}

pub fn chain_id(title: &str) -> String {
    stable_id("ch", &[title])
}
