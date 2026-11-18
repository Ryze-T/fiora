//! Shared filesystem traversal — single implementation for every module that
//! walks source trees (ledger, rules, surface). Kept tiny on purpose.

use std::io;
use std::path::{Path, PathBuf};

/// Recursively collect files under `dir` whose extension is in `exts`
/// (no dot, e.g. `["yaml", "yml"]`). Returns `(rel_path, abs_path)` pairs,
/// sorted by rel path for deterministic output.
pub fn list_files(dir: &Path, exts: &[&str]) -> io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    walk(dir, dir, exts, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(
    root: &Path,
    dir: &Path,
    exts: &[&str],
    out: &mut Vec<(String, PathBuf)>,
) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(root, &path, exts, out)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.contains(&e))
        {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            out.push((rel, path));
        }
    }
    Ok(())
}
