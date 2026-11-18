//! `fiora lab scaffold` —— trigger-prove 实验室脚手架。
//!
//! 把实战沉淀的实验室纪律一等化（本轮三个 lab 的同构流程）：
//! 真实代码 + 只桩化重依赖 + canary 无害载荷 + 正控往返 + 一次性容器即用即毁。
//! 产出目录自包含：README（纪律清单）+ Dockerfile + stub_loader.py + lab.py + run.sh。

use std::path::Path;

pub(crate) fn cmd_lab_scaffold(
    root: &Path,
    finding_id: Option<String>,
    sink: Option<String>,
    file: Option<String>,
    out: Option<std::path::PathBuf>,
    lang: &str,
) -> Result<(), String> {
    let lang = match lang {
        "python" | "java" | "go" | "node" => lang,
        other => return Err(format!("不支持的语言: {other}（可选 python|java|go|node）")),
    };
    let root = root.canonicalize().map_err(|e| format!("root: {e}"))?;

    // 定位 finding（可选）：填模板参数。
    let (sink_sym, src_file, slug) = if let Some(id) = &finding_id {
        let ledger =
            fiora_core::Ledger::open(root.join(".fiora")).map_err(|e| format!("ledger: {e}"))?;
        let f = ledger
            .load_finding(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("finding not found: {id}"))?;
        (f.sink_symbol.clone(), f.file.clone(), f.slug.clone())
    } else {
        (
            sink.unwrap_or_else(|| "TARGET_SINK".into()),
            file.unwrap_or_else(|| "path/to/module.py".into()),
            "lab".into(),
        )
    };

    let dir = out.unwrap_or_else(|| root.join("labs").join(format!("{slug}-lab")));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;

    write(
        &dir,
        "README.md",
        &readme(&slug, &sink_sym, &src_file, lang),
    )?;
    write(&dir, "Dockerfile", dockerfile(lang))?;
    write(&dir, "stub_loader.py", STUB_LOADER)?;
    match lang {
        "java" => {
            write(&dir, "Lab.java", &lab_java(&src_file, &sink_sym))?;
            write(&dir, "run.sh", RUN_SH_JAVA)?;
        }
        "go" => {
            write(&dir, "lab_test.go", &lab_go(&sink_sym))?;
            write(&dir, "run.sh", RUN_SH_GO)?;
        }
        "node" => {
            write(&dir, "lab.js", &lab_node(&src_file, &sink_sym))?;
            write(&dir, "run.sh", RUN_SH_NODE)?;
        }
        _ => {
            write(&dir, "lab.py", &lab_py(&src_file, &sink_sym))?;
            write(&dir, "run.sh", RUN_SH)?;
        }
    }

    println!("实验室脚手架已生成: {}（lang={lang}）", dir.display());
    println!("  README.md      纪律清单（先读）");
    println!("  Dockerfile     一次性容器");
    println!("  stub_loader.py 通用桩加载器（只桩重依赖，sink 用真代码）");
    println!("  实验主体        canary + 正控，sink: {sink_sym}");
    println!("  run.sh         构建 + 运行（即用即毁）");
    println!("\n下一步: cd {} && bash run.sh", dir.display());
    Ok(())
}

fn write(dir: &Path, name: &str, body: &str) -> Result<(), String> {
    std::fs::write(dir.join(name), body).map_err(|e| format!("write {name}: {e}"))
}

fn readme(slug: &str, sink: &str, file: &str, lang: &str) -> String {
    format!(
        include_str!("../../assets/lab/readme.md"),
        slug = slug,
        sink = sink,
        file = file,
        lang = lang
    )
}

const DOCKERFILE: &str = include_str!("../../assets/lab/Dockerfile.python");

const DOCKERFILE_JAVA: &str = include_str!("../../assets/lab/Dockerfile.java");

const DOCKERFILE_GO: &str = include_str!("../../assets/lab/Dockerfile.go");

const DOCKERFILE_NODE: &str = include_str!("../../assets/lab/Dockerfile.node");

fn dockerfile(lang: &str) -> &'static str {
    match lang {
        "java" => DOCKERFILE_JAVA,
        "go" => DOCKERFILE_GO,
        "node" => DOCKERFILE_NODE,
        _ => DOCKERFILE,
    }
}

const STUB_LOADER: &str = include_str!("../../assets/lab/stub_loader.py");

fn lab_py(src_file: &str, sink: &str) -> String {
    format!(
        include_str!("../../assets/lab/lab.py"),
        src_file = src_file,
        sink = sink
    )
}

const RUN_SH: &str = include_str!("../../assets/lab/run.sh");

fn lab_java(src_file: &str, sink: &str) -> String {
    format!(
        include_str!("../../assets/lab/Lab.java"),
        src_file = src_file,
        sink = sink
    )
}

fn lab_go(sink: &str) -> String {
    format!(include_str!("../../assets/lab/lab_test.go"), sink = sink)
}

fn lab_node(src_file: &str, sink: &str) -> String {
    format!(
        include_str!("../../assets/lab/lab.js"),
        src_file = src_file,
        sink = sink
    )
}

const RUN_SH_JAVA: &str = include_str!("../../assets/lab/run.java.sh");

const RUN_SH_GO: &str = include_str!("../../assets/lab/run.go.sh");

const RUN_SH_NODE: &str = include_str!("../../assets/lab/run.node.sh");
