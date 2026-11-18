//! 报告溯源验收：报告的「作者」必须和这份工件真实的生产方式一致。
//!
//! 这里的反面案例是历史 bug：`run --no-ai` 在没有模型参与的情况下，仍把账本里
//! 上一轮 AI 的模型名写成这份报告的生成者（`Fiora v0.1.0 · 模型 X（pi 会话驱动）`）。

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fiora")
}

fn temp_repo(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fiora-prov-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("api")).unwrap();
    std::fs::write(
        dir.join("api/handler.go"),
        "package api\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n\t\"fmt\"\n)\n\n\
         func Query(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n\
         \tid := r.URL.Query().Get(\"id\")\n\
         \tq := fmt.Sprintf(\"select * from t where id = %s\", id)\n\
         \trows, _ := db.Query(q)\n\
         \t_ = rows\n}\n",
    )
    .unwrap();
    dir
}

fn run_no_ai(repo: &Path) {
    let out = Command::new(bin())
        .args(["run", "--root"])
        .arg(repo)
        .args(["--no-ai", "--severity", "all"])
        .output()
        .expect("fiora run");
    assert!(
        out.status.success(),
        "run --no-ai 失败: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn zero_model_delivery_never_claims_a_model_author() {
    let repo = temp_repo("zero");
    run_no_ai(&repo);

    let html = std::fs::read_to_string(repo.join("fiora-report/report.html")).unwrap();
    assert!(
        html.contains("零模型交付（scan + evidence）"),
        "报告的生成者应是零模型交付通道"
    );
    assert!(
        !html.contains("（pi 会话驱动）"),
        "零模型交付物不许挂模型作者"
    );
    assert!(
        html.contains("未产生任何判定结论"),
        "没有判定结论时必须明说，不能留白让人以为已深审"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
