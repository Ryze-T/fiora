//! 项目画像（project profiling）——识别项目类型，自动带出对应威胁族。
//!
//! 实战动机：每个新项目冷启动都要重新选威胁画像/狩猎重点；画像标签并入
//! tech tags 流（`profile:*` 前缀）后，tech_highlights 三个注入点自动生效，
//! 新项目零配置。
//!
//! 纯确定性检测（无 LLM）：manifest/依赖文件标记 + 文件类型，有界扫描。

use std::fs;
use std::path::Path;

/// 画像标签（并入 tech tags）。
pub const TAG_IAC: &str = "profile:iac";
pub const TAG_K8S_CONTROLLER: &str = "profile:k8s-controller";
pub const TAG_ML_PIPELINE: &str = "profile:ml-pipeline";
pub const TAG_WEB_SERVICE: &str = "profile:web-service";
pub const TAG_CLI_TOOL: &str = "profile:cli-tool";
pub const TAG_LIBRARY: &str = "profile:library";

const MANIFESTS: &[&str] = &[
    "package.json",
    "go.mod",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    ".fiora",
    "dist",
    "build",
    "__pycache__",
    ".venv",
];

/// 检测项目画像标签（有序：基础设施 → 控制器 → ML → 服务 → CLI → 库）。
pub fn detect_profile_tags(root: &Path) -> Vec<String> {
    let mut hay = String::new();
    for m in MANIFESTS {
        hay.push_str(&fs::read_to_string(root.join(m)).unwrap_or_default());
        hay.push('\n');
    }

    // 有界文件名/类型扫描（浅层为主，深递归受上限约束）。
    let mut has_tf = false;
    let mut has_main = false;
    let mut has_k8s_yaml = false;
    let mut scanned = 0usize;
    collect(
        root,
        0,
        &mut scanned,
        &mut has_tf,
        &mut has_main,
        &mut has_k8s_yaml,
        &mut hay,
    );

    let mut tags = Vec::new();
    if has_tf || hay.contains("terraform") {
        tags.push(TAG_IAC.to_string());
    }
    if marker_hit(
        &hay,
        &[
            "controller-runtime",
            "kubebuilder",
            "operator-sdk",
            "k8s.io/client-go",
            "CustomResourceDefinition",
            "admissionregistration",
        ],
    ) || has_k8s_yaml && hay.contains("controller")
    {
        tags.push(TAG_K8S_CONTROLLER.to_string());
    }
    if marker_hit(
        &hay,
        &[
            "torch",
            "tensorflow",
            "transformers",
            "scikit-learn",
            "sklearn",
            "diffusers",
            "vllm",
            "sglang",
            "jax",
        ],
    ) {
        tags.push(TAG_ML_PIPELINE.to_string());
    }
    if marker_hit(
        &hay,
        &[
            "fastapi",
            "flask",
            "django",
            "uvicorn",
            "gunicorn",
            "starlette",
            "gin-gonic",
            "labstack/echo",
            "spring-boot",
            "spring-web",
            "express",
            "fastify",
            "actix-web",
            "axum",
            "rocket",
            "falcon",
            "tornado",
            "hono",
        ],
    ) {
        tags.push(TAG_WEB_SERVICE.to_string());
    }
    if marker_hit(
        &hay,
        &[
            "spf13/cobra",
            "urfave/cli",
            "\"click\"",
            "\"typer\"",
            "argparse",
            "commander",
            "yargs",
            "clap",
        ],
    ) {
        tags.push(TAG_CLI_TOOL.to_string());
    }
    // 库：有 manifest 但无服务/CLI/IaC 形态。
    if tags.is_empty() && !hay.trim().is_empty() {
        tags.push(TAG_LIBRARY.to_string());
    }
    if tags.is_empty() && !has_main {
        // 无 manifest 也无 main：保持 Unknown（不硬贴标签）。
    }
    tags
}

fn marker_hit(hay: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| hay.contains(m))
}

/// 有界递归收集：文件类型判定 + 源码抽样入 hay（上限 200 文件 / 深度 4）。
fn collect(
    dir: &Path,
    depth: usize,
    scanned: &mut usize,
    has_tf: &mut bool,
    has_main: &mut bool,
    has_k8s_yaml: &mut bool,
    hay: &mut String,
) {
    if depth > 4 || *scanned >= 200 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect(
                &path,
                depth + 1,
                scanned,
                has_tf,
                has_main,
                has_k8s_yaml,
                hay,
            );
        } else {
            *scanned += 1;
            if name.ends_with(".tf") {
                *has_tf = true;
            }
            if name == "main.go" || name == "main.py" || name == "cli.go" || name == "manage.py" {
                *has_main = true;
            }
            if name.ends_with(".yaml") || name.ends_with(".yml") {
                let body = fs::read_to_string(&path).unwrap_or_default();
                if body.contains("apiVersion:")
                    && (body.contains("kind: CustomResourceDefinition")
                        || body.contains("kind: Deployment")
                        || body.contains("kind: Controller"))
                {
                    *has_k8s_yaml = true;
                }
            }
            // 源码抽样（浅层）：import/require 行进 hay，补 manifest 缺失的信号。
            if depth <= 1
                && (name.ends_with(".go")
                    || name.ends_with(".py")
                    || name.ends_with(".ts")
                    || name.ends_with(".js")
                    || name.ends_with(".java"))
            {
                let body = fs::read_to_string(&path).unwrap_or_default();
                for line in body.lines().take(40) {
                    if line.contains("import ")
                        || line.contains("require(")
                        || line.contains("from ")
                    {
                        hay.push_str(line);
                        hay.push('\n');
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, name: &str, body: &str) {
        let p = root.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, body).unwrap();
    }

    #[test]
    fn detects_web_service() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "package.json",
            r#"{"dependencies":{"express":"^4.0.0"}}"#,
        );
        let tags = detect_profile_tags(d.path());
        assert!(tags.contains(&TAG_WEB_SERVICE.to_string()), "{tags:?}");
    }

    #[test]
    fn detects_k8s_controller() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "go.mod",
            "module x\n\nrequire sigs.k8s.io/controller-runtime v0.15.0\n",
        );
        write(
            d.path(),
            "main.go",
            "package main\nimport \"sigs.k8s.io/controller-runtime\"\nfunc main() {}\n",
        );
        let tags = detect_profile_tags(d.path());
        assert!(tags.contains(&TAG_K8S_CONTROLLER.to_string()), "{tags:?}");
    }

    #[test]
    fn detects_ml_pipeline() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "requirements.txt", "torch==2.0.0\ntransformers\n");
        let tags = detect_profile_tags(d.path());
        assert!(tags.contains(&TAG_ML_PIPELINE.to_string()), "{tags:?}");
    }

    #[test]
    fn detects_cli_tool() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "go.mod",
            "module x\n\nrequire github.com/spf13/cobra v1.7.0\n",
        );
        let tags = detect_profile_tags(d.path());
        assert!(tags.contains(&TAG_CLI_TOOL.to_string()), "{tags:?}");
    }

    #[test]
    fn detects_iac() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "main.tf", "resource \"aws_s3_bucket\" \"b\" {}\n");
        let tags = detect_profile_tags(d.path());
        assert!(tags.contains(&TAG_IAC.to_string()), "{tags:?}");
    }

    #[test]
    fn library_fallback() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "pyproject.toml", "[project]\nname = \"libx\"\n");
        let tags = detect_profile_tags(d.path());
        assert!(tags.contains(&TAG_LIBRARY.to_string()), "{tags:?}");
    }
}
