//! Runtime bootstrap (`fiora runtime install`) — the "user installs only fiora"
//! promise. pi and opengrep live in `~/.fiora/runtime/`, discovered by every
//! command; if missing, this module installs them (npm for pi, GitHub release
//! for opengrep). No separate toolchain setup, no PATH edits.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PI_PKG: &str = "@earendil-works/pi-coding-agent";
pub const PI_VERSION: &str = "1.4.0";
pub const OPENGREP_VERSION: &str = "2.0.0";

/// 钉死的发行资产 SHA-256（TOFU 锚定进源码：钉值随代码评审入库，下载后逐字节
/// 校验——官方只发 cosign `.sig/.cert` 不发 SHA256SUMS，镜像/CDN/缓存投毒因此
/// 可检出）。升级 opengrep 时在本表登记新钉值（fiora 升级 PR 顺带更新）。
const OPENGREP_SHA256: &[(&str, &str)] = &[
    (
        "opengrep_linux_aarch64",
        "6257b65423a744b704af2ff9beeb8f222c2f6925236af386b56b031d4c06d6d8",
    ),
    (
        "opengrep_linux_x86",
        "37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0",
    ),
    (
        "opengrep_osx_arm64",
        "b51b3d83f165a2e0934497b8f1b08abb1c3041ef20ef911c97e04cb39af1ad55",
    ),
    (
        "opengrep_osx_x86",
        "51d2f918d7aad0afc1426bb4fbf56e32fc70c3ffd5ddb78e32e7d61e51c029a2",
    ),
];

fn sha256_hex(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// 期望哈希：`FIORA_OPENGREP_SHA256`（手动放置/新版本自证）优先，
/// 否则按资产名查钉值表；都没有 = 不校验（下载路径如实标注未校验）。
fn expected_hash(asset_name: &str) -> Option<String> {
    if let Ok(v) = std::env::var("FIORA_OPENGREP_SHA256") {
        let v = v.trim().to_ascii_lowercase();
        if !v.is_empty() {
            return Some(v);
        }
    }
    OPENGREP_SHA256
        .iter()
        .find(|(n, _)| *n == asset_name)
        .map(|(_, h)| h.to_string())
}

pub fn runtime_dir(fiora_home: &Path) -> PathBuf {
    fiora_home.join("runtime")
}

/// Ensure both runtimes exist. Returns per-runtime status lines.
pub fn ensure_runtime(fiora_home: &Path) -> Vec<String> {
    let rt = runtime_dir(fiora_home);
    fs::create_dir_all(&rt).ok();
    let mut lines = Vec::new();

    // pi: npm-installed package + zero-magic launcher script
    let pi_launcher = rt.join("pi");
    if !pi_launcher.exists() {
        lines.push(install_pi(&rt));
    } else {
        lines.push(format!("pi:       {}", pi_launcher.display()));
    }

    // opengrep: single binary from GitHub releases (manual drop-in also works)
    let og = rt.join("opengrep");
    if !og.exists() {
        lines.push(install_opengrep(&rt));
    } else {
        lines.push(format!("opengrep: {}", og.display()));
    }
    lines
}

fn install_pi(rt: &Path) -> String {
    let pkg_dir = rt.join("pi-pkg");
    let npm = Command::new("npm")
        .args([
            "install",
            "--prefix",
            pkg_dir.to_str().unwrap_or_default(),
            "--no-audit",
            "--no-fund",
            &format!("{PI_PKG}@{PI_VERSION}"),
        ])
        .output();
    match npm {
        Ok(out) if out.status.success() => {
            let launcher = rt.join("pi");
            let script = "#!/bin/sh\n\
                HERE=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n\
                CLI=\"$HERE/pi-pkg/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js\"\n\
                if command -v node >/dev/null 2>&1; then exec node \"$CLI\" \"$@\"; fi\n\
                if command -v bun  >/dev/null 2>&1; then exec bun  \"$CLI\" \"$@\"; fi\n\
                echo \"fiora runtime: node or bun is required to execute pi\" >&2\n\
                exit 1\n";
            if fs::write(&launcher, script).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755));
                }
                format!("pi:       {} (v{PI_VERSION}, bootstrapped)", launcher.display())
            } else {
                format!("pi:       install failed (cannot write {})", launcher.display())
            }
        }
        Ok(out) => format!(
            "pi:       npm install failed: {}",
            String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>()
        ),
        Err(e) => format!(
            "pi:       npm unavailable ({e}) — 安装 Node.js ≥22（pi 运行时的硬性要求；apt-get install -y nodejs npm 或 brew install node）后重跑，或设置 FIORA_PI_BIN 指向已有 pi",
        ),
    }
}

fn install_opengrep(rt: &Path) -> String {
    // 资产命名在版本间变过两代，全部候选都列上（错名只会 404 继续试）：
    //   v1.33.1：opengrep_{manylinux,musllinux}_{aarch64,x86} / opengrep_osx_{aarch64,x86}
    //   v2.0.0：opengrep_linux_{aarch64,x86} / opengrep_osx_{arm64,x86}
    let (os_names, arch_names): (&[&str], &[&str]) =
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "aarch64") => (&["linux", "manylinux", "musllinux"], &["aarch64"]),
            ("linux", "x86_64") => (&["linux", "manylinux", "musllinux"], &["x86", "x86_64"]),
            ("macos", "aarch64") => (&["osx", "macos"], &["arm64", "aarch64"]),
            ("macos", "x86_64") => (&["osx", "macos"], &["x86", "x86_64"]),
            _ => (&[], &[]),
        };

    // 下载顺序＝可信度顺序：钉版本直链（逐字节校验）先走，latest/API 发现
    // 是移动目标（无法钉值），只作兜底且**显式标注未校验**。
    let mut candidates: Vec<String> = Vec::new();
    for name in asset_names(os_names, arch_names) {
        if expected_hash(&name).is_some() {
            candidates.push(format!(
                "https://github.com/opengrep/opengrep/releases/download/v{OPENGREP_VERSION}/{name}"
            ));
        }
    }
    // API 发现（发现的名字若在钉值表里同样逐字节校验）。
    if let Ok(out) = Command::new("sh")
        .arg("-c")
        .arg("curl -fsSL --max-time 15 https://api.github.com/repos/opengrep/opengrep/releases/latest")
        .output()
    {
        if let Ok(text) = std::str::from_utf8(&out.stdout) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(assets) = v.get("assets").and_then(|a| a.as_array()) {
                    for a in assets {
                        let name = a.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let url = a
                            .get("browser_download_url")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        let os_ok = os_names.iter().any(|o| name.contains(o));
                        let arch_ok = arch_names.iter().any(|ar| name.contains(ar))
                            || name.contains("universal");
                        if os_ok && arch_ok && !url.is_empty() && !name.contains(".sig") && !name.contains(".cert") {
                            candidates.push(url.to_string());
                        }
                    }
                }
            }
        }
    }
    // latest / 旧版本直链兜底（未校验）
    for name in asset_names(os_names, arch_names) {
        candidates.push(format!(
            "https://github.com/opengrep/opengrep/releases/latest/download/{name}"
        ));
    }
    for ver in ["2.0.0", "1.33.1"] {
        for name in asset_names(os_names, arch_names) {
            candidates.push(format!(
                "https://github.com/opengrep/opengrep/releases/download/v{ver}/{name}"
            ));
        }
    }
    candidates.dedup();

    let mut unverified_note: Option<String> = None;
    for url in &candidates {
        let asset = url.rsplit('/').next().unwrap_or("").to_string();
        let tmp = rt.join("opengrep.download");
        let _ = fs::remove_file(&tmp);
        let ok = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "curl -fsSL --max-time 300 {url} -o {tmp}",
                tmp = tmp.display()
            ))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            continue;
        }
        // 逐字节校验（有钉值/环境覆盖值时）；不符即弃，绝不安装。
        match expected_hash(&asset) {
            Some(want) => match sha256_hex(&tmp) {
                Ok(got) if got == want => {}
                Ok(got) => {
                    let _ = fs::remove_file(&tmp);
                    unverified_note = Some(format!(
                        "sha256 不符（{url}）：期望 {want}，实得 {got}——已弃用该下载"
                    ));
                    continue;
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    unverified_note = Some(format!("无法计算 sha256（{e}）——已弃用该下载"));
                    continue;
                }
            },
            None => {
                unverified_note = Some(format!(
                    "{asset} 无钉值可校验（官方只发 cosign .sig/.cert）——如需强校验：cosign verify-blob --certificate <name>.cert --signature <name>.sig {asset}"
                ));
            }
        }
        let dest = rt.join("opengrep");
        let installed = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "(tar -xzf {tmp} -C {dir} 2>/dev/null || mv {tmp} {dest}) && chmod +x {dest} 2>/dev/null; true",
                tmp = tmp.display(),
                dir = rt.display(),
                dest = dest.display(),
            ))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let _ = installed;
        if dest.exists() {
            let verified = expected_hash(&asset).is_some() && unverified_note.is_none();
            let mark = if verified {
                "sha256 已校验"
            } else {
                "未校验（见告警）"
            };
            if !verified {
                if let Some(note) = &unverified_note {
                    eprintln!("opengrep: 告警：{note}");
                }
            }
            return format!("opengrep: {} (bootstrapped, {mark})", dest.display());
        }
    }
    if let Some(note) = &unverified_note {
        eprintln!("opengrep: 告警：{note}");
    }
    format!(
        "opengrep: download failed — 重试一次 `fiora doctor`（下载可能瞬时失败）；仍失败则手动放置二进制到 {} 或设置 FIORA_OPENGREP_BIN",
        rt.join("opengrep").display()
    )
}

/// 两代资产命名的笛卡尔积（错名只会 404 继续试下一个）。
fn asset_names(os_names: &[&str], arch_names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for o in os_names {
        for a in arch_names {
            out.push(format!("opengrep_{o}_{a}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST 向量：sha256("abc")。
    #[test]
    fn sha256_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            sha256_hex(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pinned_assets_resolve_a_hash_and_unknown_names_do_not() {
        assert!(expected_hash("opengrep_linux_aarch64").is_some());
        assert!(expected_hash("opengrep_osx_arm64").is_some());
        assert!(expected_hash("opengrep_manylinux_aarch64").is_none());
    }
}
