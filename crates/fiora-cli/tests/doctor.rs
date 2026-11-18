//! doctor 的门禁分级契约：必需项决定退出码，能力项（docker）只开关主动验证。
//!
//! docker 缺失 ≠ 环境坏：CI/无 docker 的机器上 doctor 必须仍然 exit 0，
//! 否则「主动验证不可用」会被误报成「环境损坏」；反过来必需项缺失必须非零。

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fiora")
}

fn run_doctor(home: &std::path::Path, root: &std::path::Path) -> (String, bool) {
    let out = Command::new(bin())
        .env("FIORA_HOME", home)
        // 封闭环境：PATH 切断——pi/opengrep 探测有 PATH 兜底，宿主机装了
        // 全局 pi 时「空 FIORA_HOME」测不出必需项缺失，测试必须与宿主无关。
        .env("PATH", "/nonexistent")
        .args(["doctor", "--root", root.to_str().unwrap(), "--json"])
        .output()
        .expect("run doctor");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        out.status.success(),
    )
}

#[test]
fn docker_is_a_capability_and_node_is_required() {
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (stdout, _) = run_doctor(home.path(), root.path());
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("doctor --json 输出");
    assert!(v.get("healthy").is_some(), "healthy 字段必须存在: {stdout}");
    assert!(
        v.get("activeVerification").is_some(),
        "activeVerification 字段必须存在（Agent 据此决定是否动态验证）: {stdout}"
    );
    let checks = v["checks"].as_array().expect("checks 数组");
    let by = |name: &str| {
        checks
            .iter()
            .find(|c| c["check"] == name)
            .unwrap_or_else(|| panic!("{name} 检查项缺失: {stdout}"))
    };
    assert_eq!(by("node")["required"], true, "node 是硬依赖");
    assert_eq!(
        by("docker")["required"],
        false,
        "docker 是能力项，不得影响门禁"
    );
}

#[test]
fn missing_required_items_fail_the_gate_but_capabilities_do_not() {
    // 空 FIORA_HOME = pi 运行时缺失（必需项）→ 必须非零退出。
    let home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (_, ok) = run_doctor(home.path(), root.path());
    assert!(!ok, "必需项缺失时 doctor 必须 exit 非零（CI 门禁）");
}
