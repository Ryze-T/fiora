#!/usr/bin/env bash
set -euo pipefail
IMAGE="fiora-lab:$(basename "$PWD")"
REPO="${REPO_PATH:?设置 REPO_PATH=真实仓库根目录（只读挂载）}"
docker build -t "$IMAGE" .
# go.mod 里用 replace 把目标模块指到 /work（实验前按需补 go.mod）
docker run --rm -v "$REPO":/work:ro "$IMAGE" bash -lc "go mod init lab 2>/dev/null || true; go test -v ./..."
echo "[CLEAN] 容器即用即毁（--rm）"
