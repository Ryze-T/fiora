//! Technology detection (DESIGN.md §3): sentinel files -> tech tags.
//!
//! One signal feeds three consumers: rule gating, prompt threat highlights,
//! and the report's technology map.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TechReport {
    pub tags: Vec<String>,
}

pub fn detect(root: &Path) -> TechReport {
    let mut tags = Vec::new();
    let read = |name: &str| fs::read_to_string(root.join(name)).unwrap_or_default();

    // ---- JS/TS ----
    let pkg = read("package.json");
    if !pkg.is_empty() {
        let has = |dep: &str| pkg.contains(&format!("\"{dep}\""));
        for (dep, tag) in [
            ("next", "nextjs"),
            ("react", "react"),
            ("express", "express"),
            ("fastify", "fastify"),
            ("hono", "hono"),
            ("koa", "koa"),
            ("@nestjs/core", "nestjs"),
            ("remix", "remix"),
            ("@sveltejs/kit", "sveltekit"),
            ("nuxt", "nuxt"),
            ("jsonwebtoken", "jwt"),
            ("kafkajs", "kafka"),
            ("ioredis", "redis"),
            ("mongoose", "mongodb"),
            ("protobufjs", "protobuf"),
            ("@grpc/grpc-js", "grpc"),
        ] {
            if has(dep) {
                tags.push(tag.to_string());
            }
        }
        if !pkg.is_empty() {
            tags.push("node".to_string());
        }
    }

    // ---- Go ----
    let gomod = read("go.mod");
    if !gomod.is_empty() {
        tags.push("go".to_string());
        for (dep, tag) in [
            ("github.com/gin-gonic/gin", "gin"),
            ("github.com/labstack/echo", "echo"),
            ("github.com/gofiber/fiber", "fiber"),
            ("github.com/go-chi/chi", "chi"),
            ("github.com/gorilla/mux", "gorilla"),
            ("github.com/zeromicro/go-zero", "gozero"),
            ("github.com/go-kratos/kratos", "kratos"),
            ("k8s.io/client-go", "kubernetes"),
            ("sigs.k8s.io/controller-runtime", "kubernetes"),
            ("k8s.io/apiserver", "kubernetes"),
            ("k8s.io/apimachinery", "kubernetes"),
            ("google.golang.org/grpc", "grpc"),
            ("github.com/segmentio/kafka-go", "kafka"),
            ("github.com/Shopify/sarama", "kafka"),
            ("github.com/redis/go-redis", "redis"),
            ("github.com/go-redis/redis", "redis"),
            ("go.mongodb.org/mongo-driver", "mongodb"),
            ("github.com/aws/aws-sdk-go", "cloudsdk"),
            ("github.com/golang-jwt/jwt", "jwt"),
            ("github.com/gogo/protobuf", "protobuf"),
        ] {
            if gomod.contains(dep) && !tags.contains(&tag.to_string()) {
                tags.push(tag.to_string());
            }
        }
    }

    // ---- Python ----
    let py = format!(
        "{}{}{}",
        read("requirements.txt"),
        read("pyproject.toml"),
        read("setup.py")
    );
    if !py.is_empty() {
        tags.push("python".to_string());
        for (dep, tag) in [
            ("django", "django"),
            ("fastapi", "fastapi"),
            ("flask", "flask"),
            ("tornado", "tornado"),
            ("starlette", "starlette"),
            ("celery", "taskqueue"),
            ("kafka", "kafka"),
            ("redis", "redis"),
            ("boto3", "cloudsdk"),
            ("pyjwt", "jwt"),
            ("pyyaml", "serialization"),
            ("lxml", "xml"),
            ("pickle", "serialization"),
        ] {
            if py.to_lowercase().contains(dep) {
                tags.push(tag.to_string());
            }
        }
    }

    // ---- Java / JVM ----
    let jvm = format!("{}{}", read("pom.xml"), read("build.gradle"));
    if !jvm.is_empty() {
        tags.push("java".to_string());
        for (dep, tag) in [
            ("spring-boot", "spring"),
            ("org.springframework", "spring"),
            ("micronaut", "micronaut"),
            ("ktor", "ktor"),
        ] {
            if jvm.contains(dep) {
                tags.push(tag.to_string());
            }
        }
    }

    tags.dedup();
    TechReport { tags }
}
