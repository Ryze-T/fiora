//! `fiora-core` — L0 state core of the Fiora audit harness.
//!
//! Three-entity append-only audit ledger (FileRecord / Finding / Chain),
//! evidence attachments, TTL-lease scheduling and cost accounting.
//! See DESIGN.md for the full design.

pub mod config;
pub mod credentials;
pub mod family;
pub mod fsutil;
pub mod id;
pub mod ledger;
pub mod types;
pub mod util;

pub use config::{ModelSpec, Profile, ProjectConfig, ResolvedModels};
pub use credentials::Credentials;
pub use ledger::Ledger;
pub use types::*;
