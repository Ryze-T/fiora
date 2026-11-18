#!/usr/bin/env bash
set -euo pipefail
IMAGE="fiora-lab:$(basename "$PWD")"
REPO="${REPO_PATH:?设置 REPO_PATH=真实仓库根目录（只读挂载）}"
docker build -t "$IMAGE" .
docker run --rm -v "$REPO":/work:ro "$IMAGE" node /app/lab.js
echo "[CLEAN] 容器即用即毁（--rm）"
