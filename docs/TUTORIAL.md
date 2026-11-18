# Fiora 上手教程（10 分钟跑通第一次审计）

> **前提**：Node.js ≥22.19（唯一系统依赖，内嵌 Agent 运行时 pi 的硬性要求）。规则引擎（OpenGrep）与内嵌 Agent 运行时（pi）由 `fiora init` 自动拉取；环境验证不归 fiora。

> 目标：从零到一份可交付的审计报告。四步：装 → 初始化 → 跑 → 读报告。

## 0. 前置

- macOS / Linux（Windows 走 WSL）
- Node ≥ 22.19 或 Bun（pi 运行时硬性要求，`fiora init` 自动引导 pi 本体）

（环境验证由工作台 Agent 负责，需要 Docker 与否取决于验证目标，审计本身不用。）

## 1. 安装

```bash
# ① 预编译二进制（推荐：静态链接，解压即用；四平台见 Releases）
curl -fsSL https://github.com/Ryze-T/fiora/releases/latest/download/fiora-macos-arm64.tar.gz | tar xz
export PATH="$PWD/fiora-macos-arm64:$PATH"   # linux-x64 / linux-arm64 / macos-x64 同理

# ② 或从源码构建
cargo build --release && export PATH="$PWD/target/release:$PATH"
```

## 2. 初始化（一次）

```bash
cd <你要审计的仓库>
fiora init --model openai/gpt-5.5 --api-key sk-xxx
# 自定义网关：--base-url https://gw.example.com/v1 [--api openai-completions|anthropic-messages]
# key 想留在环境变量里：--api-key-env MY_KEY
```

`init` 自动完成：工作区 + 模型配置 + 凭据（chmod 600）+ 三级规则库 + pi/OpenGrep 运行时自举 + 环境自检。
体检不放心就 `fiora doctor`。

**强烈建议**：编辑仓库根的 `INFO.md`（业务/核心资产/信任边界三段），它注入所有判定 prompt，写清楚判定质量显著提升。

## 3. 跑审计

```bash
fiora run                      # 全流水线；大仓库加 --workers 4
```

进度：`fiora status` 随时看账本（文件/发现/链计数）。中断就重跑同命令，断点续跑。

## 4. 读报告

打开 `fiora-report/report.html`（单文件、离线、可转发）：

```
执行摘要 → 风险总览仪表盘（自动统计）
→ 一、RCE 风险链路分析（最高优）：mermaid 攻击链 + 证据表 + 触发条件
→ 二、其余风险链路分析：速览表 + 详情卡 + 负向结论（已否决可审计）
→ 三、风险复现与 PoC：前置条件 / 复现步骤（一键复制）/ 预期 vs 实际 / 验证徽章
→ 四、方法说明与覆盖率（含部署形态 × 风险面矩阵）
```

左侧目录自动高亮；「复现与 PoC ↓ / ↑ 返回链路分析」双向跳转；按严重度筛选。

## 5. 进阶：把验证做实（工作台 Agent 负责）

> **产品定位**：fiora 判定（code-proof 封顶），环境验证归工作台 Agent（pi 等 coding agent）。
> 报告附机器可读验证清单，Agent 按清单起环境验证，结论回填。

```bash
# Agent 读验证清单（report.json 的 verificationChecklist）
#   每条 TP 带：族/档位/CWE/前置/repro/建议验证等级/打法提示

# Agent 验证后回填真值（诚实三级 + 证伪）
fiora verify record --finding <id> --level trigger-prove --note "lab 实测：canary 落盘"
```

验证等级：`live-prove`（真实执行实锤）> `trigger-prove`（真实代码加载执行）>
`code-proof`（静态证明）> `disproved`（证伪），**没跑过的绝不标已实测**。
验证纪律（canary 无害化/一次性环境/正控往返）见 SKILL.md 验证章。

## 6. 常见任务速查

| 任务 | 命令 |
|---|---|
| 只改了几个文件，增量审 | `fiora scan && fiora evidence && fiora process && fiora report` |
| 补丁修没修好 | `fiora verify diff --pre v1 --post v2` |
| 报告文字太长 | `fiora refine`（短句分点精炼）/ `fiora localize`（中文化） |
| 缺影响/PoC | `fiora enrich` |
| 加团队规则 | `fiora rules add team-rules.yaml --project`（git 共享） |
| 改 prompt 试判定风格 | 编辑 `~/.fiora/prompts/judge.md`（不改代码） |

## 7. 踩坑速查

| 现象 | 处理 |
|---|---|
| `pi binary not found` | `fiora init` 自举；或 `FIORA_PI_BIN=$(which pi)` |
| opengrep 缺失 | 放 `~/.fiora/runtime/opengrep` 或 `FIORA_OPENGREP_BIN` |
| 模型鉴权失败 | `fiora init --api-key`；确认模型 id 与 provider 匹配 |
| 想换模型重跑 | 改 `.fiora/config.json` 或 `--model`，直接 `fiora process`，稳定身份合并，旧结论不丢 |
| 判定输出偶发损坏 | 已内建容错（结论同义词归一 + 坏条目进拒答日志） |
