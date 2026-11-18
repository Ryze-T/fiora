//! User-level credential store (`~/.fiora/credentials.json`, chmod 600).
//!
//! The API key is held HERE — never in project config, never in git, never in
//! the audit ledger. `fiora init` writes it once; every spawn injects it into
//! the agent runtime's environment (pi reads standard provider env vars).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

impl Credentials {
    pub fn load(fiora_home: &Path) -> Self {
        fs::read_to_string(fiora_home.join("credentials.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, fiora_home: &Path) -> std::io::Result<()> {
        fs::create_dir_all(fiora_home)?;
        let path = fiora_home.join("credentials.json");
        fs::write(&path, serde_json::to_string_pretty(self).unwrap())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
