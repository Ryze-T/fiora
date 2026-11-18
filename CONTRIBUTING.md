# 贡献指南

感谢你为 fiora 做贡献。这是一个讲究「可测量」的项目：**任何行为改动都必须能证明不掉分**。

## 开发环境

```bash
git clone <repo> && cd fiora
cargo build
cargo test                      # 160 测试
cargo clippy --all-targets -- -D warnings   # 0 警告门禁
cargo fmt --check               # 格式门禁
```

系统依赖：Node.js ≥18（pi 运行时自举需要）；`fiora eval` 需要 opengrep（CI 自动装）。

## 三道质量门禁（PR 必须全过）

| 门禁 | 命令 | 要求 |
|---|---|---|
| 静态 | `cargo clippy --all-targets -- -D warnings` | 0 警告 |
| 测试 | `cargo test --workspace` | 全绿 |
| **下限回归** | `cargo run --release -p fiora-cli -- eval --corpus corpus --rule-only` | **规则通道 recall 必须 100%**（分母只含 `visible_to_rule` 的期望；标注为规则不可见的期望若被规则命中，CI 直接失败，那说明语料标注错了） |

设计公理：规则通道=下限（同类静态工具能挖的必须全挖到）。任何让 recall 掉出 100%
的改动都会被 CI 拒绝，除非你同时补充 corpus 案例**证明**新行为的正确性并说明为何旧
行为是错的。

含 AI 判定改动的（prompt/判定协议/guard 表），建议附一次 `fiora eval --corpus corpus`
全量分数（recall/precision/$/TP），前后对照。`precision` 只在判定通道是测量值，
候选通道报 `n/a`，请不要拿候选数去凑精确率。

新增语料时，`case.json` 里的 `visible_to_rule: false` 用于标注「单文件规则看不见」的
问题（跨文件数据流、路由挂载语义等）；这类语料是语义通道边际价值的度量尺，
不要为了凑 recall 把它们标成可见。

## 贡献类型与入口

### 1. 加规则（最常见，改数据不改代码）

- 格式：Semgrep YAML；三级目录（builtin 只读 → `~/.fiora/rules/` → `<repo>/.fiora/rules/`，同 id 高级覆盖低级）；
- **必须带 corpus 案例**：`corpus/<case>/`（`case.json` ground truth + `repo/` 最小复现源码）；
- 规则噪音收窄经验（假阳性模式、精确上下文）比多报好，宽进严出在判定层，不在规则层。

### 2. 加语料案例

```
corpus/<kebab-case-name>/
├── case.json    # {"name","description","expected":[{file,category,sink_symbol?}]}
└── repo/        # 最小可复现源码树（不要带 .fiora/ 运行态，会被 gitignore）
```

案例要求：最小（只含目标模式）、真实（来自实战或公开 CVE 的简化）、单一（一个案例一个模式）。

### 3. 改判定协议 / prompt

- Prompt 是运行时数据（P8）：内置文本放在 `crates/fiora-processor/assets/prompts/*.md`
  （`include_str!` 内联，与用户覆盖同一格式），`prompts.rs` 只留装配代码；
  用户可经 `~/.fiora/prompts/` 覆盖，不要把逻辑写进 prompt，逻辑在代码里；
- 判定契约改动（TP 必带 impact/preconditions/repro_pack/证据链）需在 DESIGN.md
  同步更新判定章节。

### 4. 改报告版式

**先改 `docs/REPORT-TEMPLATE.md`（规范），再改实现，契约测试同步**，
`crates/fiora-report/tests/report.rs` 锁结构；离线性（零外部资源）是硬契约。

### 5. 新语言支持

入口：`fiora-core/src/fsutil.rs`（扩展名）→ `fiora-scanner/src/surface.rs`（入口面）
→ `fiora-evidence/src/callchain.rs`（tree-sitter 提取器）→ corpus 至少 3 案例。

## 提交纪律

- 一个 PR 一件事；commit message 说清 why（`cargo fmt` 已全仓统一，勿混入功能改动）；
- 中英文均可，代码注释风格跟随所在文件；
- 报告/文档改动需自查离线打开效果。

## 行为准则

- 安全工具社区的默认美德：诚实（判定≠验证、负向结论也是产出）；
- 对事不对人；拒绝夸大（「RCE」标签必须有 execution facts 支撑）。
