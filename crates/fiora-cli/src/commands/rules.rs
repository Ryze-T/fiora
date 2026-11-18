//! `fiora rules` 命令组（DESIGN.md §2）。

use fiora_scanner::{RuleRegistry, RuleSource};

/// 待入库/待校验文件自身的规则数——`RuleRegistry::load` 总是先装载内置语料，
/// 直接取 len() 会把内置 87 条一起数进「入库 N 条」（1 条规则报 88 条的现场）。
fn file_rule_count(reg: &RuleRegistry) -> usize {
    reg.iter()
        .filter(|r| r.source == RuleSource::Project)
        .count()
}
use std::path::Path;

use crate::support::dirs_fiora;

pub(crate) fn cmd_rules_list(root: &Path) -> Result<(), String> {
    use std::path::PathBuf;
    let user_dir = dirs_fiora().join("rules");
    // 三级全载：此前 project 层传 None，项目规则「入账成功但看不见」
    let project_dir = PathBuf::from(root).join(".fiora").join("rules");
    let registry =
        RuleRegistry::load(Some(&user_dir), Some(&project_dir)).map_err(|e| e.to_string())?;
    println!("{:<8} {:<10} {:<36} languages", "origin", "severity", "id");
    for r in registry.iter() {
        println!(
            "{:<8} {:<10} {:<36} {}",
            r.origin(),
            r.spec.severity,
            r.spec.id,
            r.spec.languages.join(",")
        );
    }
    println!("total: {}", registry.len());
    Ok(())
}

/// `fiora rules add <file-or-dir>` —— 规则/规则包入用户库（先校验后落盘）。
/// 目录 = 规则包（社区包/团队包导入：逐文件校验，坏规则拒入且整包不落盘）。
pub(crate) fn cmd_rules_add(file: &Path, to_project: bool, root: &Path) -> Result<(), String> {
    if file.is_dir() {
        let mut total = 0usize;
        let mut entries: Vec<_> = std::fs::read_dir(file)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|x| x.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        entries.sort();
        if entries.is_empty() {
            return Err(format!("{}: 目录内无 .yaml/.yml 规则文件", file.display()));
        }
        // 整包校验先行：任一坏规则 → 整包拒入（干净语义）
        for p in &entries {
            let text = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
            let tmp = std::env::temp_dir().join(format!("fiora-pack-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
            std::fs::write(tmp.join("check.yaml"), &text).map_err(|e| e.to_string())?;
            let probe = RuleRegistry::load(None, Some(&tmp))
                .map_err(|e| format!("{}: 规则校验失败（整包拒入）：{e}", p.display()))?;
            std::fs::remove_dir_all(&tmp).ok();
            total += file_rule_count(&probe);
        }
        let dest_dir = if to_project {
            root.join(".fiora").join("rules")
        } else {
            dirs_fiora().join("rules")
        };
        std::fs::create_dir_all(&dest_dir).map_err(|e| e.to_string())?;
        for p in &entries {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            std::fs::copy(p, dest_dir.join(&name)).map_err(|e| e.to_string())?;
        }
        println!(
            "rules: 规则包 {} 个文件 / {} 条规则入 {}",
            entries.len(),
            total,
            dest_dir.display()
        );
        return Ok(());
    }
    let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
    // 校验：必须能被三级注册表解析（结构合法、id 合法）
    let tmp = std::env::temp_dir().join(format!("fiora-rule-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    std::fs::write(tmp.join("check.yaml"), &text).map_err(|e| e.to_string())?;
    let probe = RuleRegistry::load(None, Some(&tmp)).map_err(|e| format!("规则校验失败：{e}"))?;
    std::fs::remove_dir_all(&tmp).ok();

    let dest_dir = if to_project {
        root.join(".fiora").join("rules")
    } else {
        dirs_fiora().join("rules")
    };
    std::fs::create_dir_all(&dest_dir).map_err(|e| e.to_string())?;
    let name = file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dest = dest_dir.join(&name);
    std::fs::copy(file, &dest).map_err(|e| e.to_string())?;
    println!(
        "rules: {} 条规则入 {}（id 冲突时高级覆盖低级；现库共 {} 条）",
        file_rule_count(&probe),
        dest.display(),
        probe.len()
    );
    Ok(())
}

/// `fiora rules validate [file]` —— 规则体检查验（不合法即报错退出）。
pub(crate) fn cmd_rules_validate(file: Option<&Path>) -> Result<(), String> {
    match file {
        Some(f) => {
            let text = std::fs::read_to_string(f).map_err(|e| e.to_string())?;
            let tmp = std::env::temp_dir().join(format!("fiora-rule-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
            std::fs::write(tmp.join("check.yaml"), &text).map_err(|e| e.to_string())?;
            let r = RuleRegistry::load(None, Some(&tmp));
            std::fs::remove_dir_all(&tmp).ok();
            let reg = r.map_err(|e| format!("✗ {e}"))?;
            println!("✓ {} 条规则通过结构校验", file_rule_count(&reg));
            Ok(())
        }
        None => {
            let reg = RuleRegistry::load(Some(&dirs_fiora().join("rules")), None)
                .map_err(|e| format!("✗ {e}"))?;
            println!("✓ 用户库 {} 条规则通过结构校验", reg.len());
            Ok(())
        }
    }
}
